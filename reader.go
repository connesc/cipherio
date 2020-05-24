package cipherio

import (
	"crypto/cipher"
	"io"
)

type blockReader struct {
	src       io.Reader
	blockMode cipher.BlockMode
	blockSize int
	buf       []byte // used to store remaining bytes (before or after crypting)
	crypted   int    // if > 0, then buf contains remaining crypted bytes
	eof       bool
}

// NewBlockReader wraps the given Reader to add on-the-fly encryption or decryption using the
// given BlockMode.
//
// The input must be aligned to the cipher block size: ErrUnexpectedEOF is returned if EOF is
// reached in the middle of a block.
//
// This Reader avoids buffering and copies as much as possible. A call to Read leads to at most
// one Read from the wrapped Reader and at most one call to CryptBlocks. When possible,
// (en|de)cryption happens inplace in the destination buffer.
//
// There is no dynamic allocation: an internal buffer of BlockSize bytes is used to store both
// incomplete blocks (not yet (en|de)crypted) and partially read blocks (already (en|de)crypted).
//
// The wrapped Reader is guaranteed to never be consumed beyond the last requested block. This
// means that it is safe to stop reading from this Reader at a block boundary and then resume
// reading from the wrapped Reader for another purpose.
func NewBlockReader(src io.Reader, blockMode cipher.BlockMode) io.Reader {
	blockSize := blockMode.BlockSize()

	return &blockReader{
		src:       src,
		blockMode: blockMode,
		blockSize: blockSize,
		buf:       make([]byte, 0, blockSize),
		crypted:   0,
		eof:       false,
	}
}

func (r *blockReader) Read(p []byte) (int, error) {
	count := 0

	if r.crypted > 0 {
		copied := copy(p, r.buf[r.blockSize-r.crypted:])
		p = p[copied:]
		count += copied
		r.crypted -= copied
		if r.crypted > 0 {
			return count, nil
		}
		r.buf = r.buf[:0]
	}

	if r.eof {
		return count, io.EOF
	}
	if len(p) == 0 {
		return count, nil
	}

	if len(p) < r.blockSize {
		n, err := r.src.Read(r.buf[len(r.buf):r.blockSize])
		r.buf = r.buf[:len(r.buf)+n]
		if len(r.buf) == r.blockSize {
			r.blockMode.CryptBlocks(r.buf, r.buf)
			copied := copy(p, r.buf)
			count += copied
			r.crypted = r.blockSize - copied
		}
		if err == io.EOF {
			if r.crypted > 0 {
				err = nil
				r.eof = true
			} else if len(r.buf) > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
		return count, err
	}

	n, err := r.src.Read(p[len(r.buf):])
	available := len(r.buf) + n
	buffered := available % r.blockSize
	crypted := available - buffered

	if crypted > 0 {
		copy(p, r.buf)
		r.buf = r.buf[:0]
		r.blockMode.CryptBlocks(p[:crypted], p[:crypted])
		count += crypted
	}

	newlyBuffered := buffered - len(r.buf)
	r.buf = r.buf[:buffered]
	copy(r.buf[buffered-newlyBuffered:], p[available-newlyBuffered:])

	if err == io.EOF && buffered > 0 {
		err = io.ErrUnexpectedEOF
	}
	return count, err
}
