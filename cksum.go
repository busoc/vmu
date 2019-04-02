package vmu

import (
	"encoding/binary"
	"hash"
)

var defaultSum hrdlSum

type hrdlSum struct {
	sum uint32
}

func SumHRDL() hash.Hash32 {
	var v hrdlSum
	return &v
}

func Sum(bs []byte) uint32 {
	defer defaultSum.Reset()

	defaultSum.Write(bs)
	return defaultSum.Sum32()
}

func (h *hrdlSum) Size() int      { return 4 }
func (h *hrdlSum) BlockSize() int { return 32 }
func (h *hrdlSum) Reset()         { h.sum = 0 }

func (h *hrdlSum) Sum(bs []byte) []byte {
	defer h.Reset()

	h.Write(bs)
	vs := make([]byte, h.Size())
	binary.LittleEndian.PutUint32(vs, h.sum)
	return vs
}

func (h *hrdlSum) Sum32() uint32 {
	return h.sum
}

func (h *hrdlSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		h.sum += uint32(bs[i])
	}
	return len(bs), nil
}
