package ctlog

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"fmt"
)

type HashTuple struct {
	Hash  [32]byte
	Index [5]byte
}

type HashFile []HashTuple

// this is all kinds of wrong, but this is more just example code.
// 1. this is unsafe to call concurrently
// 2. the hash passed into this function should be the leaf hash, not the
// certificate fingerprint hash.
// 3. this should be modified to take in the full hashes and indexes changed
// and modify them all together, rather than one at a time.
func (l *Log) PutHash(ctx context.Context, hash [32]byte, index uint64) error {
	byteStream, err := l.c.Backend.Fetch(ctx, "/hashes/"+hex.EncodeToString(hash[0:2])+"/"+hex.EncodeToString(hash[2:4]))

	var hashFile HashFile

	// println("got 1")

	if err != nil {
		// TODO: check if this is a 404 error, otherwise this is unsafe
		hashFile = make(HashFile, 0)
	} else {
		reader := bytes.NewReader(byteStream)
		dec := gob.NewDecoder(reader)
		err = dec.Decode(&hashFile)
		if err != nil {
			return err
		}
	}

	hashFile = append(hashFile, HashTuple{Hash: hash, Index: [5]byte{byte(index >> 32), byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index)}})

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(hashFile)
	if err != nil {
		return err
	}

	// this is commented because it causes test storage mutex to deadlock.
	err = l.c.Backend.Upload(ctx, "/hashes/"+hex.EncodeToString(hash[0:2])+"/"+hex.EncodeToString(hash[2:4]), buf.Bytes(), &UploadOptions{Compress: true})
	if err != nil {
		return err
	}

	return nil
}

func (l *Log) GetHash(ctx context.Context, hash [32]byte) (uint64, error) {
	byteStream, err := l.c.Backend.Fetch(ctx, "/hashes/"+hex.EncodeToString(hash[0:2])+"/"+hex.EncodeToString(hash[2:4]))

	if err != nil {
		return 0, err
	}

	reader := bytes.NewReader(byteStream)
	dec := gob.NewDecoder(reader)
	var hashFile HashFile
	err = dec.Decode(&hashFile)
	if err != nil {
		return 0, err
	}

	// iterate over the slice to find the index with the correct hash
	for _, tuple := range hashFile {
		if bytes.Equal(tuple.Hash[:], hash[:]) {
			return uint64(tuple.Index[0])<<32 | uint64(tuple.Index[1])<<24 | uint64(tuple.Index[2])<<16 | uint64(tuple.Index[3])<<8 | uint64(tuple.Index[4]), nil
		}
	}
	return 0, fmt.Errorf("hash not found")
}
