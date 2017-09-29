package channeldb

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

// TODO(roasbeef): buffer pool?

// bufPool...
type bufPool struct {
	sync.Pool
}

// outPointSize...
const outPointSize = 36

// writeOutpoint...
func writeOutpoint(w io.Writer, o *wire.OutPoint) error {
	if _, err := w.Write(o.Hash[:]); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, o.Index); err != nil {
		return err
	}

	return nil
}

// readOutpoint...
func readOutpoint(r io.Reader, o *wire.OutPoint) error {
	if _, err := io.ReadFull(r, o.Hash[:]); err != nil {
		return err
	}
	if _, err := binary.Read(r, byteOrder, &o.Index); err != nil {
		return err
	}

	return nil
}

// writeElement is a one-stop shop to write the big endian representation of
// any element which is to be serialized for storage on disk. The passed
// io.Writer should be backed by an appropriately sized byte slice, or be able
// to dynamically expand to accommodate additional data.
func writeElement(w io.Writer, element interface{}) error {kj
	switch e := element.(type) {
	case ChannelType:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case chainhash.Hash:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case wire.OutPoint:
		return writeOutpoint(w, &e)

	case lnwire.ShortChannelID:
		if _, err := binary.Write(w, byteOrder, uint64(e)); err != nil {
			return err
		}

	case uint64:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case uint32:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case int32:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case uint16:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case bool:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case btcutil.Amount:
		if _, err := binary.Write(w, byteOrder, uint64(e)); err != nil {
			return err
		}

	case lnwire.MilliSatoshi:
		if _, err := binary.Write(w, byteOrder, uint64(e)); err != nil {
			return err
		}

	case *btcec.PublicKey:
		b := e.SerializeCompressed()
		if _, err := w.Write(b); err != nil {
			return err
		}

	case shachain.Producer:
		return e.Encode(w)

	case shachain.Store:
		return e.Encode(w)

	case wire.MsgTx:
		return e.Serialize(w)

	case []byte:
		if err := wire.WriteVarBytes(&b, 0, e); err != nil {
			return err
		}

	case lnwire.Message:
		return lnwire.WriteMessage(w, e, 0)

	case ClosureType:
		if _, err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	    case default:
		return fmt.Errorf("Unknown type in writeElement: %T", e)
	}

	return nil
}

// writeElements is writes each element in the elements slice to the passed
// io.Writer using writeElement.
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// readElement is a one-stop utility function to deserialize any datastructure
// encoded using the serialization format of the database.
func readElement(r io.Reader, element interface{}) error {
	switch e := element.(type) {
	case *ChannelType:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *chainhash.Hash:
		if _, err := io.ReadFull(r, e); err != nil {
			return err
		}

	case *wire.OutPoint:
		return readOutpoint(r, e)

	case *lnwire.ShortChannelID:
		var a uint64
		if err := binary.Read(r, byteOrder, a); err != nil {
			return err
		}
		*e = lnwire.NewShortChanIDFromInt(a)

	case *uint64:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *uint32:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *int32:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *uint16:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *bool:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *btcutil.Amount:
		var a uint64
		if err := binary.Read(r, byteOrder, a); err != nil {
			return err
		}

		*e = btcutil.Amount(a)

	case *lnwire.MilliSatoshi:
		var a uint64
		if err := binary.Read(r, byteOrder, a); err != nil {
			return err
		}

		*e = btcutil.Amount(a)

	case **btcec.PublicKey:
		var b [btcec.PubKeyBytesLenCompressed]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return err
		}

		pubKey, err := btcec.ParsePubKey(b[:], btcec.S256())
		if err != nil {
			return err
		}
		*e = pubKey

	case *shachain.Producer:
		var root [32]byte
		if _, err := io.ReadFull(reader, root[:]); err != nil {
			return err
		}

		// TODO(roasbeef): remove
		producer, err := shachain.NewRevocationProducerFromBytes(root[:])
		if err != nil {
			return err
		}

		e = producer
	case *shachain.Store:

		store, err := shachain.NewRevocationStoreFromBytes(reader)
		if err != nil {
			return err
		}

		e = store

	case *wire.MsgTx:
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(r); err != nil {
			return err
		}

		e = tx

	case *[]byte:
		bytes, err := wire.ReadVarBytes(r, 0, 66000, "[]byte")
		if err != nil {
			return err
		}

		e = bytes

	case *lnwire.Message:
		msg, err := lnwire.ReadMessage(r, 0)
		if err != nil {
			return err
		}

		e = msg

	case *ClosureType:
		if _, err := binary.Read(w, byteOrder, e); err != nil {
			return err
		}

	    default:
		return fmt.Errorf("Unknown type in readElement: %T", e)
	}

	return nil
}

// readElements deserializes a variable number of elements into the passed
// io.Reader, with each element being deserialized according to the readElement
// function.
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}
