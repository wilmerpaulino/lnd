package channeldb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/boltdb/bolt"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	// closedChannelBucket stores summarization information concerning
	// previously open, but now closed channels.
	closedChannelBucket = []byte("closed-chan-bucket")

	// openChanBucket stores all the currently open channels. This bucket
	// has a second, nested bucket which is keyed by a node's ID. Within
	// that node ID bucket, all attributes required to track, update, and
	// close a channel are stored.
	//
	// openChan -> nodeID -> chanPoint
	//
	// TODO(roasbeef): flesh out comment
	openChannelBucket = []byte("open-chan-bucket")

	// chanInfoKey can be accessed within the bucket for a channel
	// (identified by it's chanPoint). This key stores all the static
	// information for a channel which is decided at the end of  the
	// funding flow.
	chanInfoKey = []byte("chan-info-key")

	// chanCommitmentKey can be accessed within the sub-bucket for a
	// particular channel. This key stores the up to date commitment state
	// for a particular channel party. Appending a 0 to the end of this key
	// indicates it's the commitment for the local party, and appending a 1
	// to the end of this key indicates it's the commitment for the remote
	// party.
	chanCommitmentKey = []byte("chan-commitment-key")

	// revocationStateKey stores their current revocation hash, our
	// preimage producer and their preimage store.
	revocationStateKey = []byte("revocation-state-key")

	// commitDiffKey stores the current pending commitment state we've
	// extended to the remote party (if any). Each time we propose a new
	// state, we store the information necessary to reconstruct this state
	// from the prior commitment. This allows us to resync the remote party
	// to their expected state in the case of message loss.
	commitDiffKey = []byte("commit-diff-key")

	// channelLogKey is dedicated for storing the necessary delta state
	// between channel updates required to re-construct a past state in
	// order to punish a counterparty attempting a non-cooperative channel
	// closure. This key should be accessed from within the sub-bucket of a
	// target channel, identified by its channel point.
	channelLogKey = []byte("channel-log-key")
)

var (
	// ErrNoCommitmentsFound...
	ErrNoCommitmentsFound = fmt.Errorf("no commitments found")

	// ErrNoChanInfoFound
	ErrNoChanInfoFound = fmt.Errorf("no chan info found")

	// ErrNoChanInfoFound...
	ErrNoRevocationsFound = fmt.Errorf("no revocations found")
)

// ChannelType is an enum-like type that describes one of several possible
// channel types. Each open channel is associated with a particular type as the
// channel type may determine how higher level operations are conducted such as
// fee negotiation, channel closing, the format of HTLCs, etc.
// TODO(roasbeef): split up per-chain?
type ChannelType uint8

const (
	// NOTE: iota isn't used here for this enum needs to be stable
	// long-term as it will be persisted to the database.

	// SingleFunder represents a channel wherein one party solely funds the
	// entire capacity of the channel.
	SingleFunder = 0

	// DualFunder represents a channel wherein both parties contribute
	// funds towards the total capacity of the channel. The channel may be
	// funded symmetrically or asymmetrically.
	DualFunder = 1
)

// ChannelConstraints represents a set of constraints meant to allow a node to
// limit their exposure, enact flow control and ensure that all HTLC's are
// economically relevant This struct will be mirrored for both sides of the
// channel, as each side will enforce various constraints that MUST be adhered
// to for the life time of the channel. The parameters for each of these
// constraints is static for the duration of the channel, meaning the channel
// must be teared down for them to change.
type ChannelConstraints struct {
	// DustLimit is the threhsold (in satoshis) below which any outputs
	// should be trimmed. When an output is trimmed, it isn't materialized
	// as an actual output, but is instead burned to miner's fees.
	DustLimit btcutil.Amount

	// MaxPendingAmount is the maximum pending HTLC value that can be
	// present within the channel at a particular time. This value is set
	// by the initiator of the channel and must be upheld at all times.
	MaxPendingAmount lnwire.MilliSatoshi

	// ChanReserve is an absolute reservation on the channel for this
	// particular node. This means that the current settled balance for
	// this node CANNOT dip below the reservation amount. This acts as a
	// defense against costless attacks when either side no longer has any
	// skin in the game.
	ChanReserve btcutil.Amount

	// MinHTLC is the minimum HTLC accepted for a direction of the channel.
	// If any HTLC's below this amount are offered, then the HTLC will be
	// rejected. This, in tandem with the dust limit allows a node to
	// regulate the smallest HTLC that it deems economically relevant.
	MinHTLC lnwire.MilliSatoshi

	// MaxAcceptedHtlcs is the maximum amount of HTLC's that are to be
	// accepted by the owner of this set of constraints. This allows each
	// node to limit their over all exposure to HTLC's that may need to be
	// acted upon in the case of a unilateral channel closure or a contract
	// breach.
	MaxAcceptedHtlcs uint16
}

// ChannelConfig is a struct that houses the various configuration opens for
// channels. Each side maintains an instance of this configuration file as it
// governs: how the funding and commitment transaction to be created, the
// nature of HTLC's allotted, the keys to be used for delivery, and relative
// time lock parameters.
type ChannelConfig struct {
	// ChannelConstraints is the set of constraints that must be upheld for
	// the duration of the channel for the owner of this channel
	// configuration. Constraints govern a number of flow control related
	// parameters, also including the smallest HTLC that will be accepted
	// by a participant.
	ChannelConstraints

	// CsvDelay is the relative time lock delay expressed in blocks. Any
	// settled outputs that pay to the owner of this channel configuration
	// MUST ensure that the delay branch uses this value as the relative
	// time lock. Similarly, any HTLC's offered by this node should use
	// this value as well.
	CsvDelay uint16

	// MultiSigKey is the key to be used within the 2-of-2 output script
	// for the owner of this channel config.
	MultiSigKey *btcec.PublicKey

	// RevocationBasePoint is the base public key to be used when deriving
	// revocation keys for the remote node's commitment transaction. This
	// will be combined along with a per commitment secret to derive a
	// unique revocation key for each state.
	RevocationBasePoint *btcec.PublicKey

	// PaymentBasePoint is the based public key to be used when deriving
	// the key used within the non-delayed pay-to-self output on the
	// commitment transaction for a node. This will be combined with a
	// tweak derived from the per-commitment point to ensure unique keys
	// for each commitment transaction.
	PaymentBasePoint *btcec.PublicKey

	// DelayBasePoint is the based public key to be used when deriving the
	// key used within the delayed pay-to-self output on the commitment
	// transaction for a node. This will be combined with a tweak derived
	// from the per-commitment point to ensure unique keys for each
	// commitment transaction.
	DelayBasePoint *btcec.PublicKey
}

// ChannelCommitment is a snapshot of the commitment state at a particular
// point in the commitment chain. With each state transition, a snapshot of the
// current state along with all non-settled HTLCs are recorded. These snapshots
// detail the state of the _remote_ party's commitment at a particular state
// number.  For ourselves (the local node) we ONLY store our most recent
// (unrevoked) state for safety purposes.
type ChannelCommitment struct {
	// CommitHeight is the update number that this ChannelDelta represents
	// the total number of commitment updates to this point. This can be
	// viewed as sort of a "commitment height" as this number is
	// monotonically increasing.
	CommitHeight uint64

	// LocalLogIndex...
	LocalLogIndex uint64

	// RemoteLogIndex...
	RemoteLogIndex uint64

	// LocalBalance is the current available settled balance within the
	// channel directly spendable by us.
	LocalBalance lnwire.MilliSatoshi

	// RemoteBalance is the current available settled balance within the
	// channel directly spendable by the remote node.
	RemoteBalance lnwire.MilliSatoshi

	// CommitFee is the amount calculated to be paid in fees for the
	// current set of commitment transactions. The fee amount is persisted
	// with the channel in order to allow the fee amount to be removed and
	// recalculated with each channel state update, including updates that
	// happen after a system restart.
	CommitFee btcutil.Amount

	// FeePerKw is the min satoshis/kilo-weight that should be paid within
	// the commitment transaction for the entire duration of the channel's
	// lifetime. This field may be updated during normal operation of the
	// channel as on-chain conditions change.
	FeePerKw btcutil.Amount

	// TotalMSatSent is the total number of milli-satoshis we've sent
	// within this channel.
	TotalMSatSent lnwire.MilliSatoshi

	// TotalMSatReceived is the total number of milli-satoshis we've
	// received within this channel.
	TotalMSatReceived lnwire.MilliSatoshi

	// CommitTx is the latest version of the commitment state, broadcast
	// able by us.
	CommitTx wire.MsgTx

	// CommitSig is one half of the signature required to fully complete
	// the script for the commitment transaction above. This is the
	// signature signed by the remote party for our version of the
	// commitment transactions.
	CommitSig []byte

	// Htlcs is the set of HTLC's that are pending at this particular
	// commitment height.
	Htlcs []HTLC
}

// OpenChannel encapsulates the persistent and dynamic state of an open channel
// with a remote node. An open channel supports several options for on-disk
// serialization depending on the exact context. Full (upon channel creation)
// state commitments, and partial (due to a commitment update) writes are
// supported. Each partial write due to a state update appends the new update
// to an on-disk log, which can then subsequently be queried in order to
// "time-travel" to a prior state.
type OpenChannel struct {
	// ChanType denotes which type of channel this is.
	ChanType ChannelType

	// ChainHash is a hash which represents the blockchain that this
	// channel will be opened within. This value is typically the genesis
	// hash. In the case that the original chain went through a contentious
	// hard-fork, then this value will be tweaked using the unique fork
	// point on each branch.
	ChainHash chainhash.Hash

	// FundingOutpoint is the outpoint of the final funding transaction.
	// This value uniquely and globally identities the channel within the
	// target blockchain as specified by the chain hash parameter.
	FundingOutpoint wire.OutPoint

	// ShortChanID encodes the exact location in the chain in which the
	// channel was initially confirmed. This includes: the block height,
	// transaction index, and the output within the target transaction.
	ShortChanID lnwire.ShortChannelID

	// IsPending indicates whether a channel's funding transaction has been
	// confirmed.
	IsPending bool

	// IsInitiator is a bool which indicates if we were the original
	// initiator for the channel. This value may affect how higher levels
	// negotiate fees, or close the channel.
	IsInitiator bool

	// FundingBroadcastHeight is the height in which the funding
	// transaction was broadcast. This value can be used by higher level
	// sub-systems to determine if a channel is stale and/or should have
	// been confirmed before a certain height.
	FundingBroadcastHeight uint32

	// NumConfsRequired is the number of confirmations a channel's funding
	// transaction must have received in order to be considered available
	// for normal transactional use.
	NumConfsRequired uint16

	// IdentityPub is the identity public key of the remote node this
	// channel has been established with.
	IdentityPub *btcec.PublicKey

	// Capacity is the total capacity of this channel.
	Capacity btcutil.Amount

	// LocalChanCfg is the channel configuration for the local node.
	LocalChanCfg ChannelConfig

	// RemoteChanCfg is the channel configuration for the remote node.
	RemoteChanCfg ChannelConfig

	// LocalCommitment...
	LocalCommitment ChannelCommitment

	// RemoteCommitment...
	RemoteCommitment ChannelCommitment

	// RemoteCurrentRevocation is the current revocation for their
	// commitment transaction. However, since this the derived public key,
	// we don't yet have the private key so we aren't yet able to verify
	// that it's actually in the hash chain.
	RemoteCurrentRevocation *btcec.PublicKey

	// RemoteNextRevocation is the revocation key to be used for the *next*
	// commitment transaction we create for the local node. Within the
	// specification, this value is referred to as the
	// per-commitment-point.
	RemoteNextRevocation *btcec.PublicKey

	// RevocationProducer is used to generate the revocation in such a way
	// that remote side might store it efficiently and have the ability to
	// restore the revocation by index if needed. Current implementation of
	// secret producer is shachain producer.
	RevocationProducer shachain.Producer

	// RevocationStore is used to efficiently store the revocations for
	// previous channels states sent to us by remote side. Current
	// implementation of secret store is shachain store.
	RevocationStore shachain.Store

	// TODO(roasbeef): eww
	Db *DB

	sync.RWMutex
}

// FullSync serializes, and writes to disk the *full* channel state, using
// both the active channel bucket to store the prefixed column fields, and the
// remote node's ID to store the remainder of the channel state.
func (c *OpenChannel) FullSync() error {
	c.Lock()
	defer c.Unlock()

	return c.Db.Update(c.fullSync)
}

// fullSync is an internal version of the FullSync method which allows callers
// to sync the contents of an OpenChannel while re-using an existing database
// transaction.
//
// TODO(roasbeef): add helper funcs to create scoped update
func (c *OpenChannel) fullSync(tx *bolt.Tx) error {
	// First fetch the top level bucket which stores all data related to
	// current, active channels.
	openChanBucket, err := tx.CreateBucketIfNotExists(openChannelBucket)
	if err != nil {
		return err
	}

	// Within this top level bucket, fetch the bucket dedicated to storing
	// open channel data specific to the remote node.
	nodePub := c.IdentityPub.SerializeCompressed()
	nodeChanBucket, err := openChanBucket.CreateBucketIfNotExists(nodePub)
	if err != nil {
		return err
	}

	// With the bucket for the node fetched, we can now go down another
	// level, creating the bucket (if it doesn't exist), for this channel
	// iteslf.
	var chanPointBuf bytes.Buffer
	chanPointBuf.Grow(outPointSize)
	if err := writeOutpoint(&chanPointBuf, &c.FundingOutpoint); err != nil {
		return err
	}
	chanBucket, err := nodeChanBucket.CreateBucketIfNotExists(
		chanPointBuf.Bytes(),
	)
	if err != nil {
		return err
	}

	return putOpenChannel(chanBucket, c)
}

// putChannel serializes, and stores the current state of the channel in its
// entirety.
func putOpenChannel(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	// First, we'll write out all the relatively static fields, that are
	// decided upon initial channel creation.
	if err := putChanInfo(chanBucket, channel); err != nil {
		return fmt.Errorf("unable to store chan info: %v", err)
	}

	// With the static channel info written out, we'll now write out the
	// current commitment state for both parties.
	if err := putChanCommitments(chanBucket, channel); err != nil {
		return fmt.Errorf("unable to store chan commitments: %v", err)
	}

	// Finally, we'll write out the revocation state for both parties
	// within a distinct key space.
	if err := putChanRevocationState(chanBucket, channel); err != nil {
		return fmt.Errorf("unable to store chan revocations: %v", err)
	}

	return nil
}

func putChanInfo(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	var w bytes.Buffer
	if err := writeElements(&w,
		channel.ChanType, channel.ChainHash, channel.FundingOutpoint,
		channel.ShortChanID, channel.IsPending, channel.IsInitiator,
		channel.FundingBroadcastHeight, channel.NumConfsRequired,
		channel.IdentityPub, channel.Capacity,
	); err != nil {
		return err
	}

	writeChanConfig := func(b io.Writer, c *ChannelConfig) error {
		return writeElements(b,
			c.DustLimit, c.MaxPendingAmount, c.ChanReserve, c.MinHTLC,
			c.MaxAcceptedHtlcs, c.CsvDelay, c.MultiSigKey,
			c.RevocationBasePoint, c.PaymentBasePoint, c.DelayBasePoint,
		)
	}
	if err := writeChanConfig(&w, &channel.LocalChanCfg); err != nil {
		return err
	}
	if err := writeChanConfig(&w, &channel.RemoteChanCfg); err != nil {
		return err
	}

	return chanBucket.Put(chanInfoKey, w.Bytes())
}

func putChanCommitment(chanBucket *bolt.Bucket, c *ChannelCommitment,
	local bool) error {

	var key []byte
	copy(key[:], chanCommitmentKey)
	if local {
		key = append(key, byte(0x00))
	} else {
		key = append(key, byte(0x01))
	}

	var b bytes.Buffer
	if err := writeElements(&b,
		c.CommitHeight, c.LocalLogIndex, c.RemoteLogIndex, c.LocalBalance,
		c.RemoteBalance, c.CommitFee, c.FeePerKw, c.TotalMSatSent,
		c.TotalMSatReceived, c.CommitTx, c.CommitSig,
	); err != nil {
		return err
	}

	if err := serializeHtlcs(&b, c.Htlcs); err != nil {
		return err
	}

	return chanBucket.Put(key, b.Bytes())
}

func putChanCommitments(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	err := putChanCommitment(chanBucket, &channel.LocalCommitment, true)
	if err != nil {
		return err
	}

	return putChanCommitment(chanBucket, &channel.LocalCommitment, false)
}

func putChanRevocationState(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	var b bytes.Buffer
	err := writeElements(&b,
		channel.RemoteCurrentRevocation, channel.RemoteNextRevocation,
		channel.RevocationProducer, channel.RevocationStore)
	if err != nil {
		return err
	}

	return chanBucket.Put(revocationStateKey, b.Bytes())
}

// fetchOpenChannel retrieves, and deserializes (including decrypting
// sensitive) the complete channel currently active with the passed nodeID.
func fetchOpenChannel(chanBucket *bolt.Bucket,
	chanPoint *wire.OutPoint) (*OpenChannel, error) {

	var err error
	channel := &OpenChannel{
		FundingOutpoint: *chanPoint,
	}

	// First, we'll read all the static information that changes less
	// frequently from disk.
	if err := fetchChanInfo(chanBucket, channel); err != nil {
		return nil, fmt.Errorf("unable to fetch chan info: %v", err)
	}

	// With the static information read, we'll now read the current
	// commitment state for both sides of the channel.
	if err := fetchChanCommitments(chanBucket, channel); err != nil {
		return nil, fmt.Errorf("unable to fetch chan commitments: %v", err)
	}

	// Finally, we'll retrieve the current revocation state so we can
	// properly
	if err := fetchChanRevocationState(chanBucket, channel); err != nil {
		return nil, fmt.Errorf("unable to fetch chan revocations: %v", err)
	}

	return channel, nil
}

func fetchChanInfo(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	infoBytes := chanBucket.Get(chanInfoKey)
	if infoBytes == nil {
		return ErrNoChanInfoFound
	}
	r := bytes.NewReader(infoBytes)

	if err := readElements(r,
		&channel.ChanType, &channel.ChainHash, &channel.FundingOutpoint,
		&channel.ShortChanID, &channel.IsPending, &channel.IsInitiator,
		&channel.FundingBroadcastHeight, &channel.NumConfsRequired,
		&channel.IdentityPub, &channel.Capacity,
	); err != nil {
		return err
	}

	readChanConfig := func(b io.Reader, c *ChannelConfig) error {
		return readElements(b,
			&c.DustLimit, &c.MaxPendingAmount, &c.ChanReserve,
			&c.MinHTLC, &c.MaxAcceptedHtlcs, &c.CsvDelay,
			&c.MultiSigKey, &c.RevocationBasePoint,
			&c.PaymentBasePoint, &c.DelayBasePoint,
		)
	}
	if err := readChanConfig(r, &channel.LocalChanCfg); err != nil {
		return err
	}
	if err := readChanConfig(r, &channel.RemoteChanCfg); err != nil {
		return err
	}

	return nil
}

func fetchChanCommitment(chanBucket *bolt.Bucket, local bool) (ChannelCommitment, error) {
	var key []byte
	copy(key[:], chanCommitmentKey)
	if local {
		key = append(key, byte(0x00))
	} else {
		key = append(key, byte(0x01))
	}

	var c ChannelCommitment

	commitBytes := chanBucket.Get(key)
	if commitBytes == nil {
		return c, ErrNoCommitmentsFound
	}

	r := bytes.NewReader(commitBytes)

	err := readElements(r,
		&c.CommitHeight, &c.LocalLogIndex, &c.RemoteLogIndex,
		&c.LocalBalance, &c.RemoteBalance, &c.CommitFee, &c.FeePerKw,
		&c.TotalMSatSent, &c.TotalMSatReceived, &c.CommitTx, &c.CommitSig,
	)
	if err != nil {
		return c, err
	}

	c.Htlcs, err = deserializeHtlcs(r)
	if err != nil {
		return c, err
	}

	return c, nil
}

func fetchChanCommitments(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	var err error

	channel.LocalCommitment, err = fetchChanCommitment(chanBucket, true)
	if err != nil {
		return err
	}
	channel.RemoteCommitment, err = fetchChanCommitment(chanBucket, false)
	if err != nil {
		return err
	}

	return nil
}

func fetchChanRevocationState(chanBucket *bolt.Bucket, channel *OpenChannel) error {
	revBytes := chanBucket.Get(revocationStateKey)
	if revBytes == nil {
		return ErrNoRevocationsFound
	}
	r := bytes.NewReader(revBytes)

	return readElements(r,
		&channel.RemoteCurrentRevocation, &channel.RemoteNextRevocation,
		&channel.RevocationProducer, &channel.RevocationStore,
	)
}

// SyncPending writes the contents of the channel to the database while it's in
// the pending (waiting for funding confirmation) state. The IsPending flag
// will be set to true. When the channel's funding transaction is confirmed,
// the channel should be marked as "open" and the IsPending flag set to false.
// Note that this function also creates a LinkNode relationship between this
// newly created channel and a new LinkNode instance. This allows listing all
// channels in the database globally, or according to the LinkNode they were
// created with.
//
// TODO(roasbeef): addr param should eventually be a lnwire.NetAddress type
// that includes service bits.
func (c *OpenChannel) SyncPending(addr *net.TCPAddr, pendingHeight uint32) error {
	c.Lock()
	defer c.Unlock()

	c.FundingBroadcastHeight = pendingHeight

	return c.Db.Update(func(tx *bolt.Tx) error {
		// First, sync all the persistent channel state to disk.
		if err := c.fullSync(tx); err != nil {
			return err
		}

		nodeInfoBucket, err := tx.CreateBucketIfNotExists(nodeInfoBucket)
		if err != nil {
			return err
		}

		// If a LinkNode for this identity public key already exists,
		// then we can exit early.
		nodePub := c.IdentityPub.SerializeCompressed()
		if nodeInfoBucket.Get(nodePub) != nil {
			return nil
		}

		// Next, we need to establish a (possibly) new LinkNode
		// relationship for this channel. The LinkNode metadata
		// contains reachability, up-time, and service bits related
		// information.
		linkNode := c.Db.NewLinkNode(wire.MainNet, c.IdentityPub, addr)

		// TODO(roasbeef): do away with link node all together?

		return putLinkNode(nodeInfoBucket, linkNode)
	})
}

// UpdateCommitment updates the commitment state for the specified party
// (remote or local). The commitment stat completely describes the balance
// state at this point in the commitment chain. This method its to be called on
// two occasions: when we revoke our prior commitment state, and when the
// remote party revokes their prior commitment state.
func (c *OpenChannel) UpdateCommitment(newCommitment *ChannelCommitment,
	isLocal bool) error {

	c.Lock()
	defer c.Unlock()

	err := c.Db.Update(func(tx *bolt.Tx) error {
		// First fetch the top level bucket which stores all data
		// related to current, active channels.
		openChanBucket, err := tx.CreateBucketIfNotExists(openChannelBucket)
		if err != nil {
			return err
		}

		// Within this top level bucket, fetch the bucket dedicated to
		// storing open channel data specific to the remote node.
		id := c.IdentityPub.SerializeCompressed()
		nodeChanBucket, err := chanBucket.CreateBucketIfNotExists(id)
		if err != nil {
			return err
		}

		// With the bucket for the node fetched, we can now go down
		// another level, creating the bucket (if it doesn't exist),
		// for this channel iteslf.
		var chanPointBuf bytes.Buffer
		chanPointBuf.Grow(outPointSize)
		err := writeOutpoint(&chanPointBuf, &c.FundingOutpoint)
		if err != nil {
			return err
		}
		chanBucket, err := nodeChanBucket.CreateBucketIfNotExists(
			chanPointBuf.Bytes(),
		)
		if err != nil {
			return err
		}

		// With the proper bucket fetched, we'll now write toe latest
		// commitment state to dis for the target party.
		return putChanCommitment(chanBucket, newCommitment, isLocal)
	})
	if err != nil {
		return err
	}

	if local {
		c.LocalCommitment = newCommitment
	} else {
		c.RemoteCommitment = newCommitment
	}

	return nil
}

// HTLC is the on-disk representation of a hash time-locked contract. HTLCs
// are contained within ChannelDeltas which encode the current state of the
// commitment between state updates.
type HTLC struct {
	// Signature is the signature for the second level covenant transaction
	// for this HTLC. The second level transaction is a timeout tx in the
	// case that this is an outgoing HTLC, and a success tx in the case
	// that this is an incoming HTLC.
	//
	// TODO(roasbeef): make [64]byte instead?
	Signature []byte

	// RHash is the payment hash of the HTLC.
	RHash [32]byte

	// Amt is the amount of milli-satoshis this HTLC escrows.
	Amt lnwire.MilliSatoshi

	// RefundTimeout is the absolute timeout on the HTLC that the sender
	// must wait before reclaiming the funds in limbo.
	RefundTimeout uint32

	// OutputIndex is the output index for this particular HTLC output
	// within the commitment transaction.
	OutputIndex int32

	// Incoming denotes whether we're the receiver or the sender of this
	// HTLC.
	Incoming bool

	// OnionBlob is an opaque blob which is used to complete multi-hop
	// routing.
	OnionBlob []byte

	// LogIndex...
	LogIndex uint64
}

func serializeHtlcs(b io.Writer, htlcs []HTLC) error {
	numHtlcs := uint16(len(htlcs))
	if err := writeElement(b, numHtlcs); err != nil {
		return err
	}

	for _, htlc := range htlcs {
		if err := writeElements(b,
			htlc.Signature, htlc.RHash, htlc.Amt, htlc.RefundTimeout,
			htlc.OutputIndex, htlc.Incoming, htlc.OnionBlob[:],
			htlc.LogIndex,
		); err != nil {
			return err
		}
	}

	return nil
}

func deserializeHtlcs(r io.Reader) ([]HTLC, error) {
	var numHtlcs uint16
	if err := readElement(r, &numHtlcs); err != nil {
		return nil, err
	}

	htlcs := make([]HTLC, numHtlcs)
	for i := uint16(0); i < numHtlcs; i++ {
		if err := readElements(r,
			&htlcs[i].Signature, &htlcs[i].RHash, &htlcs[i].Amt,
			&htlcs[i].RefundTimeout,
			&htlcs[i].OutputIndex, &htlcs[i].Incoming, htlcs[i].OnionBlob,
			&htlcs[i].LogIndex,
		); err != nil {
			return htlcs, err
		}
	}

	return htlcs, nil
}

// Copy returns a full copy of the target HTLC.
func (h *HTLC) Copy() HTLC {
	clone := HTLC{
		Incoming:      h.Incoming,
		Amt:           h.Amt,
		RefundTimeout: h.RefundTimeout,
		OutputIndex:   h.OutputIndex,
	}
	copy(clone.Signature[:], h.Signature)
	copy(clone.RHash[:], h.RHash[:])

	return clone
}

// CommitDiff represents the delta needed to apply the state transition between
// two subsequewnt commitment states. Given state N and state N+1, one is able
// to apply the set of messages contained within the CommitDiff to N to arrive
// at state N+1. Each time a new commitmetn is extended, we'll write a new
// commitment (along with the full comitment state) to disk so we can
// re-transmit the state in the case of a connection loss or message drop.
//
// TODO(roasbeef): NEED TO ALSO WRITE TO DISK ON COMMIT RECV!!!
type CommitDiff struct {
	// PendingHeight is the next height in the commitment chain that this
	// CommitDiff would create if applied on top of the current remote
	// commiemtn.
	PendingHeight uint64

	// PendingCommitment is the full commitment state that one would arrive
	// at by applying the set of messages contained in the UpdateDiff to
	// the prior accepted commitment.
	//
	// TODO(roasbeef): should contain OUR sig
	PendingCommitment ChannelCommitment

	// UpdateDiff is the set of messages sent prior to the commitment state
	// transition in question. Upon reconnection, if we detect that they
	// don't have the commitment, then we re-send thsis along with the
	// proper signature.
	//
	// TODO(roasbeef): also need the index along with?
	UpdateDiff []lnwire.Message
}

// encode...
func (d *CommitDiff) encode(r io.Reader) error {
	if err := binary.Read(r, byteOrder, &d.PendingHeight); err != nil {
		return err
	}

	delta, err := deserializeChannelDelta(r)
	if err != nil {
		return err
	}
	d.PendingCommitment = *delta

	var length uint16
	if err := binary.Read(r, byteOrder, &length); err != nil {
		return err
	}
	d.Updates = make([]lnwire.Message, length)

	for i, _ := range d.Updates {
		msg, err := lnwire.ReadMessage(r, 0)
		if err != nil {
			return err
		}
		d.Updates[i] = msg
	}

	return nil
}

// decode...
func (d *CommitDiff) decode(w io.Writer) error {
	if err := binary.Write(w, byteOrder, d.PendingHeight); err != nil {
		return err
	}

	if err := serializeChannelDelta(w, &d.PendingCommitment); err != nil {
		return err
	}

	if err := binary.Write(w, byteOrder, uint16(len(d.Updates))); err != nil {
		return err
	}

	for _, msg := range d.Updates {
		if _, err := lnwire.WriteMessage(w, msg, 0); err != nil {
			return err
		}
	}

	return nil
}

// AddCommitDiff...
//
// TODO(roasbeef): make method on OpenChannel itself
//
// TODO(roasbeef): really need: big, commit, etc for txn style stuffs
func AddCommitDiff(db *DB, fundingOutpoint *wire.OutPoint, diff *CommitDiff) error {

	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(commitDiffBucket)
		if err != nil {
			return err
		}

		var b bytes.Buffer
		if err := diff.decode(&b); err != nil {
			return err
		}

		var outpoint bytes.Buffer
		if err := writeOutpoint(&outpoint, fundingOutpoint); err != nil {
			return err
		}

		key := []byte("cdf")
		key = append(key, outpoint.Bytes()...)
		return bucket.Put(key, b.Bytes())
	})
}

// FetchCommitDiff...
//
// TODO(roasbeef): make method on OpenChannel itself
func FetchCommitDiff(db *DB, fundingOutpoint *wire.OutPoint) (*CommitDiff, error) {
	var diff *CommitDiff
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(commitDiffBucket)
		if bucket == nil {
			return errors.New("commit diff bucket haven't been found")
		}

		var outpoint bytes.Buffer
		if err := writeOutpoint(&outpoint, fundingOutpoint); err != nil {
			return err
		}

		key := []byte("cdf")
		key = append(key, outpoint.Bytes()...)
		data := bucket.Get(key)
		if data == nil {
			return errors.New("unable to find commit diff")
		}

		diff = &CommitDiff{}
		return diff.encode(bytes.NewReader(data))
	})

	return diff, err
}

// InsertNextRevocation inserts the _next_ commitment point (revocation) into
// the database, and also modifies the internal RemoteNextRevocation attribute
// to point to the passed key. This method is to be using during final channel
// set up, _after_ the channel has been fully confirmed.
//
// NOTE: If this method isn't called, then the target channel won't be able to
// propose new states for the commitment state of the remote party.
func (c *OpenChannel) InsertNextRevocation(revKey *btcec.PublicKey) error {
	c.Lock()
	defer c.Unlock()

	return c.Db.Update(func(tx *bolt.Tx) error {
		chanBucket, err := tx.CreateBucketIfNotExists(openChannelBucket)
		if err != nil {
			return err
		}

		id := c.IdentityPub.SerializeCompressed()
		nodeChanBucket, err := chanBucket.CreateBucketIfNotExists(id)
		if err != nil {
			return err
		}

		c.RemoteNextRevocation = revKey
		return putChanRevocationState(nodeChanBucket, c)
	})
}

// AppendToRevocationLog records the new state transition within an on-disk
// append-only log which records all state transitions by the remote peer. In
// the case of an uncooperative broadcast of a prior state by the remote peer,
// this log can be consulted in order to reconstruct the state needed to
// rectify the situation.
func (c *OpenChannel) AppendToRevocationLog(delta *ChannelDelta) error {
	return c.Db.Update(func(tx *bolt.Tx) error {
		chanBucket, err := tx.CreateBucketIfNotExists(openChannelBucket)
		if err != nil {
			return err
		}

		id := c.IdentityPub.SerializeCompressed()
		nodeChanBucket, err := chanBucket.CreateBucketIfNotExists(id)
		if err != nil {
			return err
		}

		// Persist the latest preimage state to disk as the remote peer
		// has just added to our local preimage store, and
		// given us a new pending revocation key.
		if err := putChanRevocationState(nodeChanBucket, c); err != nil {
			return err
		}

		// With the current preimage producer/store state updated,
		// append a new log entry recording this the delta of this state
		// transition.
		// TODO(roasbeef): could make the deltas relative, would save
		// space, but then tradeoff for more disk-seeks to recover the
		// full state.
		logKey := channelLogBucket
		logBucket, err := nodeChanBucket.CreateBucketIfNotExists(logKey)
		if err != nil {
			return err
		}

		// TODO(roasbeef): fin comment -> delete diff after recv their
		// revocation
		diffBucket := tx.Bucket(commitDiffBucket)
		if diffBucket != nil {
			var outpoint bytes.Buffer
			if err := writeOutpoint(&outpoint, &c.FundingOutpoint); err != nil {
				return err
			}

			key := []byte("cdf")
			key = append(key, outpoint.Bytes()...)
			if diffBucket.Get(key) != nil {
				if err := diffBucket.Delete(key); err != nil {
					return err
				}
			}
		}

		return appendChannelLogEntry(logBucket, delta, &c.FundingOutpoint)
	})
}

// RevocationLogTail returns the "tail", or the end of the current revocation
// log. This entry represents the last previous state for the remote node's
// commitment chain. The ChannelDelta returned by this method will always lag
// one state behind the most current (unrevoked) state of the remote node's
// commitment chain.
func (c *OpenChannel) RevocationLogTail() (*ChannelDelta, error) {
	// If we haven't created any state updates yet, then we'll exit erly as
	// there's nothing to be found on disk in the revocation bucket.
	if c.NumUpdates == 0 {
		return nil, nil
	}

	var delta *ChannelDelta
	if err := c.Db.View(func(tx *bolt.Tx) error {
		chanBucket := tx.Bucket(openChannelBucket)

		nodePub := c.IdentityPub.SerializeCompressed()
		nodeChanBucket := chanBucket.Bucket(nodePub)
		if nodeChanBucket == nil {
			return ErrNoActiveChannels
		}

		logBucket := nodeChanBucket.Bucket(channelLogBucket)
		if logBucket == nil {
			return ErrNoPastDeltas
		}

		// Once we have the bucket that stores the revocation log from
		// this channel, we'll jump to the _last_ key in bucket. As we
		// store the update number on disk in a big-endian format,
		// this'll retrieve the latest entry.
		cursor := logBucket.Cursor()
		_, tailLogEntry := cursor.Last()
		logEntryReader := bytes.NewReader(tailLogEntry)

		// Once we have the entry, we'll decode it into the channel
		// delta pointer we created above.
		var dbErr error
		delta, dbErr = deserializeChannelDelta(logEntryReader)
		if dbErr != nil {
			return dbErr
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return delta, nil
}

// CommitmentHeight returns the current commitment height. The commitment
// height represents the number of updates to the commitment state to data.
// This value is always monotonically increasing. This method is provided in
// order to allow multiple instances of a particular open channel to obtain a
// consistent view of the number of channel updates to data.
func (c *OpenChannel) CommitmentHeight() (uint64, error) {
	// TODO(roasbeef): this is super hacky, remedy during refactor!!!
	o := &OpenChannel{
		FundingOutpoint: c.FundingOutpoint,
	}

	err := c.Db.View(func(tx *bolt.Tx) error {
		// Get the bucket dedicated to storing the metadata for open
		// channels.
		openChanBucket := tx.Bucket(openChannelBucket)
		if openChanBucket == nil {
			return ErrNoActiveChannels
		}

		return fetchChanNumUpdates(openChanBucket, o)
	})
	if err != nil {
		return 0, nil
	}

	return o.NumUpdates, nil
}

// FindPreviousState scans through the append-only log in an attempt to recover
// the previous channel state indicated by the update number. This method is
// intended to be used for obtaining the relevant data needed to claim all
// funds rightfully spendable in the case of an on-chain broadcast of the
// commitment transaction.
func (c *OpenChannel) FindPreviousState(updateNum uint64) (*ChannelDelta, error) {
	delta := &ChannelDelta{}

	err := c.Db.View(func(tx *bolt.Tx) error {
		chanBucket := tx.Bucket(openChannelBucket)

		nodePub := c.IdentityPub.SerializeCompressed()
		nodeChanBucket := chanBucket.Bucket(nodePub)
		if nodeChanBucket == nil {
			return ErrNoActiveChannels
		}

		logBucket := nodeChanBucket.Bucket(channelLogBucket)
		if logBucket == nil {
			return ErrNoPastDeltas
		}

		var err error
		delta, err = fetchChannelLogEntry(logBucket, &c.FundingOutpoint,
			updateNum)

		return err
	})
	if err != nil {
		return nil, err
	}

	return delta, nil
}

// ClosureType is an enum like structure that details exactly _how_ a channel
// was closed. Three closure types are currently possible: cooperative, force,
// and breach.
type ClosureType uint8

const (
	// CooperativeClose indicates that a channel has been closed
	// cooperatively.  This means that both channel peers were online and
	// signed a new transaction paying out the settled balance of the
	// contract.
	CooperativeClose ClosureType = iota

	// ForceClose indicates that one peer unilaterally broadcast their
	// current commitment state on-chain.
	ForceClose

	// BreachClose indicates that one peer attempted to broadcast a prior
	// _revoked_ channel state.
	BreachClose

	// FundingCanceled indicates that the channel never was fully opened before it
	// was marked as closed in the database. This can happen if we or the remote
	// fail at some point during the opening workflow, or we timeout waiting for
	// the funding transaction to be confirmed.
	FundingCanceled
)

// ChannelCloseSummary contains the final state of a channel at the point it
// was closed. Once a channel is closed, all the information pertaining to
// that channel within the openChannelBucket is deleted, and a compact
// summary is put in place instead.
type ChannelCloseSummary struct {
	// ChanPoint is the outpoint for this channel's funding transaction,
	// and is used as a unique identifier for the channel.
	ChanPoint wire.OutPoint

	// ClosingTXID is the txid of the transaction which ultimately closed
	// this channel.
	ClosingTXID chainhash.Hash

	// RemotePub is the public key of the remote peer that we formerly had
	// a channel with.
	RemotePub *btcec.PublicKey

	// Capacity was the total capacity of the channel.
	Capacity btcutil.Amount

	// SettledBalance is our total balance settled balance at the time of
	// channel closure. This _does not_ include the sum of any outputs that
	// have been time-locked as a result of the unilateral channel closure.
	SettledBalance btcutil.Amount

	// TimeLockedBalance is the sum of all the time-locked outputs at the
	// time of channel closure. If we triggered the force closure of this
	// channel, then this value will be non-zero if our settled output is
	// above the dust limit. If we were on the receiving side of a channel
	// force closure, then this value will be non-zero if we had any
	// outstanding outgoing HTLC's at the time of channel closure.
	TimeLockedBalance btcutil.Amount

	// CloseType details exactly _how_ the channel was closed. Three
	// closure types are possible: cooperative, force, and breach.
	CloseType ClosureType

	// IsPending indicates whether this channel is in the 'pending close'
	// state, which means the channel closing transaction has been
	// broadcast, but not confirmed yet or has not yet been fully resolved.
	// In the case of a channel that has been cooperatively closed, it will
	// no longer be considered pending as soon as the closing transaction
	// has been confirmed. However, for channel that have been force
	// closed, they'll stay marked as "pending" until _all_ the pending
	// funds have been swept.
	IsPending bool

	// TODO(roasbeef): also store short_chan_id?
}

// CloseChannel closes a previously active lightning channel. Closing a channel
// entails deleting all saved state within the database concerning this
// channel. This method also takes a struct that summarizes the state of the
// channel at closing, this compact representation will be the only component
// of a channel left over after a full closing.
func (c *OpenChannel) CloseChannel(summary *ChannelCloseSummary) error {
	return c.Db.Update(func(tx *bolt.Tx) error {
		// First fetch the top level bucket which stores all data
		// related to current, active channels.
		chanBucket := tx.Bucket(openChannelBucket)
		if chanBucket == nil {
			return ErrNoChanDBExists
		}

		// Within this top level bucket, fetch the bucket dedicated to
		// storing open channel data specific to the remote node.
		nodePub := c.IdentityPub.SerializeCompressed()
		nodeChanBucket := chanBucket.Bucket(nodePub)
		if nodeChanBucket == nil {
			return ErrNoActiveChannels
		}

		// Delete this channel ID from the node's active channel index.
		chanIndexBucket := nodeChanBucket.Bucket(chanIDBucket)
		if chanIndexBucket == nil {
			return ErrNoActiveChannels
		}

		var b bytes.Buffer
		if err := writeOutpoint(&b, &c.FundingOutpoint); err != nil {
			return err
		}

		// If this channel isn't found within the channel index bucket,
		// then it has already been deleted. So we can exit early as
		// there isn't any more work for us to do here.
		outPointBytes := b.Bytes()
		if chanIndexBucket.Get(outPointBytes) == nil {
			return nil
		}

		// Otherwise, we can safely delete the channel from the index
		// without running into any boltdb related errors by repeated
		// deletion attempts.
		if err := chanIndexBucket.Delete(outPointBytes); err != nil {
			return err
		}

		// Now that the index to this channel has been deleted, purge
		// the remaining channel metadata from the database.
		if err := deleteOpenChannel(chanBucket, nodeChanBucket,
			outPointBytes, &c.FundingOutpoint); err != nil {
			return err
		}

		// With the base channel data deleted, attempt to delte the
		// information stored within the revocation log.
		logBucket := nodeChanBucket.Bucket(channelLogBucket)
		if logBucket != nil {
			err := wipeChannelLogEntries(logBucket, &c.FundingOutpoint)
			if err != nil {
				return err
			}
		}

		// Finally, create a summary of this channel in the closed
		// channel bucket for this node.
		return putChannelCloseSummary(tx, outPointBytes, summary)
	})
}

// ChannelSnapshot is a frozen snapshot of the current channel state. A
// snapshot is detached from the original channel that generated it, providing
// read-only access to the current or prior state of an active channel.
//
// TODO(roasbeef): remove all together? pretty much just commitment
type ChannelSnapshot struct {
	// RemoteIdentity is the identity public key of the remote node that we
	// are maintaining the open channel with.
	RemoteIdentity btcec.PublicKey

	// ChannelCommitment...
	ChannelCommitment
}

// Snapshot returns a read-only snapshot of the current channel state. This
// snapshot includes information concerning the current settled balance within
// the channel, metadata detailing total flows, and any outstanding HTLCs.
func (c *OpenChannel) Snapshot() *ChannelSnapshot {
	c.RLock()
	defer c.RUnlock()

	snapshot := &ChannelSnapshot{
		RemoteIdentity:             *c.IdentityPub,
		ChannelPoint:               c.FundingOutpoint,
		Capacity:                   c.Capacity,
		LocalBalance:               c.LocalBalance,
		RemoteBalance:              c.RemoteBalance,
		NumUpdates:                 c.NumUpdates,
		CommitFee:                  c.CommitFee,
		TotalMilliSatoshisSent:     c.TotalMSatSent,
		TotalMilliSatoshisReceived: c.TotalMSatReceived,
	}

	// Copy over the current set of HTLCs to ensure the caller can't
	// mutate our internal state.
	snapshot.Htlcs = make([]HTLC, len(c.Htlcs))
	for i, h := range c.Htlcs {
		snapshot.Htlcs[i] = h.Copy()
	}

	return snapshot
}

func deleteOpenChannel(openChanBucket *bolt.Bucket, nodeChanBucket *bolt.Bucket,
	channelID []byte, o *wire.OutPoint) error {

	// TODO(roasbeef): just 3 deletes:
	//  * info, commitment, revocation, log, diff

	// First we'll delete all the "common" top level items stored outside
	// the node's channel bucket.
	if err := deleteChanCapacity(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanMinFeePerKw(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanNumUpdates(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteOurMessageIndex(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteTheirMessageIndex(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanAmountsTransferred(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanIsPending(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanConfInfo(openChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanCommitFee(openChanBucket, channelID); err != nil {
		return err
	}

	// Finally, delete all the fields directly within the node's channel
	// bucket.
	if err := deleteChannelIDs(nodeChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanConfigs(nodeChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanCommitTxns(nodeChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanFundingInfo(nodeChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteChanRevocationState(nodeChanBucket, channelID); err != nil {
		return err
	}
	if err := deleteCurrentHtlcs(nodeChanBucket, o); err != nil {
		return err
	}

	return nil
}

func makeHtlcKey(o *wire.OutPoint) [39]byte {
	var (
		n int
		k [39]byte
	)

	// chk || txid || index
	n += copy(k[:], currentHtlcKey)
	n += copy(k[n:], o.Hash[:])
	var scratch [4]byte
	byteOrder.PutUint32(scratch[:], o.Index)
	copy(k[n:], scratch[:])

	return k
}

func putCurrentHtlcs(nodeChanBucket *bolt.Bucket, htlcs []*HTLC,
	o *wire.OutPoint) error {
	var b bytes.Buffer

	for _, htlc := range htlcs {
		if err := serializeHTLC(&b, htlc); err != nil {
			return err
		}
	}

	htlcKey := makeHtlcKey(o)
	return nodeChanBucket.Put(htlcKey[:], b.Bytes())
}

func fetchCurrentHtlcs(nodeChanBucket *bolt.Bucket,
	o *wire.OutPoint) ([]*HTLC, error) {

	htlcKey := makeHtlcKey(o)
	htlcBytes := nodeChanBucket.Get(htlcKey[:])
	if htlcBytes == nil {
		return nil, nil
	}

	// TODO(roasbeef): can preallocate here
	var htlcs []*HTLC
	htlcReader := bytes.NewReader(htlcBytes)
	for htlcReader.Len() != 0 {
		htlc, err := deserializeHTLC(htlcReader)
		if err != nil {
			return nil, err
		}

		htlcs = append(htlcs, htlc)
	}

	return htlcs, nil
}

func deleteCurrentHtlcs(nodeChanBucket *bolt.Bucket, o *wire.OutPoint) error {
	htlcKey := makeHtlcKey(o)
	return nodeChanBucket.Delete(htlcKey[:])
}

func serializeChannelDelta(w io.Writer, delta *ChannelDelta) error {
	// TODO(roasbeef): could use compression here to reduce on-disk space.
	var scratch [8]byte
	byteOrder.PutUint64(scratch[:], uint64(delta.LocalBalance))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}
	byteOrder.PutUint64(scratch[:], uint64(delta.RemoteBalance))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	byteOrder.PutUint64(scratch[:], delta.UpdateNum)
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	numHtlcs := uint64(len(delta.Htlcs))
	if err := wire.WriteVarInt(w, 0, numHtlcs); err != nil {
		return err
	}
	for _, htlc := range delta.Htlcs {
		if err := serializeHTLC(w, htlc); err != nil {
			return err
		}
	}

	byteOrder.PutUint64(scratch[:], uint64(delta.CommitFee))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	byteOrder.PutUint64(scratch[:], uint64(delta.FeePerKw))
	if _, err := w.Write(scratch[:]); err != nil {
		return err
	}

	return nil
}

func deserializeChannelDelta(r io.Reader) (*ChannelDelta, error) {
	var (
		err     error
		scratch [8]byte
	)

	delta := &ChannelDelta{}

	if _, err := r.Read(scratch[:]); err != nil {
		return nil, err
	}
	delta.LocalBalance = lnwire.MilliSatoshi(byteOrder.Uint64(scratch[:]))
	if _, err := r.Read(scratch[:]); err != nil {
		return nil, err
	}
	delta.RemoteBalance = lnwire.MilliSatoshi(byteOrder.Uint64(scratch[:]))

	if _, err := r.Read(scratch[:]); err != nil {
		return nil, err
	}
	delta.UpdateNum = byteOrder.Uint64(scratch[:])

	numHtlcs, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	delta.Htlcs = make([]*HTLC, numHtlcs)
	for i := uint64(0); i < numHtlcs; i++ {
		htlc, err := deserializeHTLC(r)
		if err != nil {
			return nil, err
		}

		delta.Htlcs[i] = htlc
	}
	if _, err := r.Read(scratch[:]); err != nil {
		return nil, err
	}
	delta.CommitFee = btcutil.Amount(byteOrder.Uint64(scratch[:]))

	if _, err := r.Read(scratch[:]); err != nil {
		return nil, err
	}
	delta.FeePerKw = btcutil.Amount(byteOrder.Uint64(scratch[:]))

	return delta, nil
}

func makeLogKey(o *wire.OutPoint, updateNum uint64) [44]byte {
	var (
		scratch [8]byte
		n       int

		// txid (32) || index (4) || update_num (8)
		// 32 + 4 + 8 = 44
		k [44]byte
	)

	n += copy(k[:], o.Hash[:])

	byteOrder.PutUint32(scratch[:4], o.Index)
	n += copy(k[n:], scratch[:4])

	byteOrder.PutUint64(scratch[:], updateNum)
	copy(k[n:], scratch[:])

	return k
}

func appendChannelLogEntry(log *bolt.Bucket, delta *ChannelDelta,
	chanPoint *wire.OutPoint) error {

	var b bytes.Buffer
	if err := serializeChannelDelta(&b, delta); err != nil {
		return err
	}

	logEntrykey := makeLogKey(chanPoint, delta.UpdateNum)
	return log.Put(logEntrykey[:], b.Bytes())
}

func fetchChannelLogEntry(log *bolt.Bucket, chanPoint *wire.OutPoint,
	updateNum uint64) (*ChannelDelta, error) {

	logEntrykey := makeLogKey(chanPoint, updateNum)
	deltaBytes := log.Get(logEntrykey[:])
	if deltaBytes == nil {
		return nil, fmt.Errorf("log entry not found")
	}

	deltaReader := bytes.NewReader(deltaBytes)

	return deserializeChannelDelta(deltaReader)
}

func wipeChannelLogEntries(log *bolt.Bucket, o *wire.OutPoint) error {
	var (
		n         int
		logPrefix [32 + 4]byte
		scratch   [4]byte
	)

	// First we'll construct a key prefix that we'll use to scan through
	// and delete all the log entries related to this channel. The format
	// for log entries within the database is: txid || index || update_num.
	// We'll construct a prefix key with the first two thirds of the full
	// key to scan with and delete all entries.
	n += copy(logPrefix[:], o.Hash[:])
	byteOrder.PutUint32(scratch[:], o.Index)
	copy(logPrefix[n:], scratch[:])

	// With the prefix constructed, scan through the log bucket from the
	// starting point of the log entries for this channel. We'll keep
	// deleting keys until the prefix no longer matches.
	logCursor := log.Cursor()
	for logKey, _ := logCursor.Seek(logPrefix[:]); bytes.HasPrefix(logKey, logPrefix[:]); logKey, _ = logCursor.Next() {
		if err := log.Delete(logKey); err != nil {
			return err
		}
	}

	return nil
}
