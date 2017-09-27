package channeldb

// TODO(roasbeef): buffer pool?

// bufPool...
type bufPool struct {
    sync.Pool
}

// writeElement is a one-stop shop to write the big endian representation of
// any element which is to be serialized for storage on disk. The passed
// io.Writer should be backed by an appropriately sized byte slice, or be able
// to dynamically expand to accommodate additional data.
func writeElement(w io.Writer, element interface{}) error {
	switch e := element.(type) {
	    case ChannelType:
	    case chainhash.Hash:
	    case wire.OutPoint:
	    case lnwire.ShortChannelID:
	    case uint64:
	    case uint32:
	    case int32:
	    case uint16:
	    case bool:
	    case btcutil.Amount
	    case lnwire.MilliSatoshi:
	    case *btcec.PublicKey:
	    case shachain.Producer:
	    case shachain.Store:
	    case wire.MsgTx:
	    case []byte:
	    case lnwire.Message:
	    case ClosureType:
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
    return err
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
