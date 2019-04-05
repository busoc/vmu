package vmu

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/busoc/timutil"
)

var (
	ErrSkip     = errors.New("skip")
	ErrInvalid  = errors.New("invalid packet")
	ErrSyncword = errors.New("invalid syncword")
)

const Syncword = 0xf82e3553

const (
	UPILen        = 32
	HRDPHeaderLen = 18
	HRDLHeaderLen = 8
	VMUHeaderLen  = 16
	SCCHeaderLen  = 56
	IMGHeaderLen  = 76
)

const (
	VIC1 uint8 = iota + 1
	VIC2
	LRSD
)

const BufferSize = 8 << 20

type Packet struct {
	HRDPHeader
	VMUHeader
	DataHeader
	Data []byte
	Sum  uint32
}

func (p Packet) Missing(other Packet) uint32 {
  if p.VMUHeader.Channel != other.VMUHeader.Channel {
    return 0
  }
  diff := p.VMUHeader.Sequence - other.VMUHeader.Sequence
  if diff != p.VMUHeader.Sequence {
    diff--
  }
  return diff
}

func (p Packet) IsRealtime() bool {
	return p.VMUHeader.Origin == p.DataHeader.Origin
}

type Decoder struct {
	inner  io.Reader
	buffer []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		inner:  r,
		buffer: make([]byte, BufferSize),
	}
}

func DecodePacket(buffer []byte, data bool) (Packet, error) {
	return decodePacket(buffer, data)
}

func (d *Decoder) Decode(data bool) (p Packet, err error) {
	n, err := d.inner.Read(d.buffer)
	if err != nil {
		return
	}
	return decodePacket(d.buffer[:n], data)
}

type HRDPHeader struct {
	Size         uint32
	Error        uint16
	Channel      uint8
	Payload      uint8
	PacketCoarse uint32
	PacketFine   uint8
	HRDPCoarse   uint32
	HRDPFine     uint8
}

func (h HRDPHeader) Elapsed() time.Duration {
	return h.Archive().Sub(h.Acquisition())
}

func (h HRDPHeader) Acquisition() time.Time {
	return timutil.Join5(h.PacketCoarse, h.PacketFine)
}

func (h HRDPHeader) Archive() time.Time {
	return timutil.Join5(h.HRDPCoarse, h.HRDPFine)
}

type VMUHeader struct {
	Size     uint32
	Channel  uint8
	Origin   uint8
	Sequence uint32
	Coarse   uint32
	Fine     uint16
}

func (v VMUHeader) Timestamp() time.Time {
	return timutil.Join6(v.Coarse, v.Fine)
}

type DataHeader struct {
	Property uint8
	Origin   uint8
	AcqTime  time.Duration
	AuxTime  time.Duration
	Stream   uint16
	Counter  uint32
	UPI      [UPILen]byte
}

func (d DataHeader) UserInfo() []byte {
	return userInfo(make([]byte, UPILen), d.UPI)
}

func (d DataHeader) Acquisition() time.Time {
	return timutil.GPS.Add(d.AcqTime)
}

func (d DataHeader) Auxiliary() time.Time {
	return timutil.GPS.Add(d.AuxTime)
}

func decodePacket(buffer []byte, data bool) (p Packet, err error) {
	var offset, base int
	if len(buffer) < 4 {
		err = ErrSkip
		return
	}
	if w := binary.BigEndian.Uint32(buffer); w != Syncword {
		if p.HRDPHeader, err = decodeHRDP(buffer); err != nil {
			return
		}
		offset += HRDPHeaderLen
		base = offset
	}
	base += HRDLHeaderLen
	if p.VMUHeader, err = decodeVMU(buffer[offset:]); err != nil {
		return
	}
  expected := offset + VMUHeaderLen + HRDLHeaderLen
  switch p.VMUHeader.Channel {
  case VIC1, VIC2:
    expected += IMGHeaderLen
  case LRSD:
    expected += SCCHeaderLen
  }
  if len(buffer) < expected {
    err = ErrSkip
    return
  }

	offset += HRDLHeaderLen + VMUHeaderLen
	if p.DataHeader, err = decodeData(buffer[offset:]); err != nil {
		return
	}
	length := int(p.VMUHeader.Size) - VMUHeaderLen
	switch p.VMUHeader.Channel {
	case VIC1, VIC2:
		offset += IMGHeaderLen
		length -= IMGHeaderLen
	case LRSD:
		offset += SCCHeaderLen
		length -= SCCHeaderLen
	}
	n := len(buffer)
	if data {
		if int(length) >= n-offset {
			err = ErrSkip
			return
		}
		p.Data = append(p.Data, buffer[offset:offset+length]...)
	}

	sum := Sum(buffer[base : n-4])
	p.Sum = binary.LittleEndian.Uint32(buffer[n-4:])
	if p.Sum != sum {
		err = ErrInvalid
	}
	return
}

func decodeHRDP(body []byte) (HRDPHeader, error) {
  var h HRDPHeader
  if len(body) < HRDPHeaderLen {
    return h, ErrSkip
  }

	h.Size = binary.LittleEndian.Uint32(body)
	h.Error = binary.BigEndian.Uint16(body[4:])
	h.Payload = uint8(body[6])
	h.Channel = uint8(body[7])
	h.PacketCoarse = binary.BigEndian.Uint32(body[8:])
	h.PacketFine = uint8(body[12])
	h.HRDPCoarse = binary.BigEndian.Uint32(body[13:])
	h.HRDPFine = uint8(body[17])

	return h, nil
}

func decodeVMU(body []byte) (VMUHeader, error) {
	var v VMUHeader
  if len(body) < HRDLHeaderLen+VMUHeaderLen {
    return v, ErrSkip
  }

	if word := binary.BigEndian.Uint32(body); word != Syncword {
		return v, ErrSyncword
	}
	v.Size = binary.LittleEndian.Uint32(body[4:])
	v.Channel = uint8(body[8])
	v.Origin = uint8(body[9])
	v.Sequence = binary.LittleEndian.Uint32(body[12:])
	v.Coarse = binary.LittleEndian.Uint32(body[16:])
	v.Fine = binary.LittleEndian.Uint16(body[20:])

	return v, nil
}

func decodeData(body []byte) (DataHeader, error) {
	var v DataHeader

	v.Property = body[0]
  var expected int
  switch v.Property >> 4 {
  case 1:
    expected = SCCHeaderLen
  case 2:
    expected = IMGHeaderLen
  default:
    return v, ErrSkip
  }
  if len(body) < expected {
    return v, ErrSkip
  }
	v.Stream = binary.LittleEndian.Uint16(body[1:])
	v.Counter = binary.LittleEndian.Uint32(body[3:])
	v.AcqTime = time.Duration(binary.LittleEndian.Uint64(body[7:]))
	v.AuxTime = time.Duration(binary.LittleEndian.Uint64(body[15:]))
	v.Origin = body[23]

	switch v.Property >> 4 {
	case 1: // science
		copy(v.UPI[:], body[24:])
	case 2: // image
		copy(v.UPI[:], body[44:])
	}
	return v, nil
}
