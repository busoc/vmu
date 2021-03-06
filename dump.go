package vmu

import (
	"encoding/binary"
	"io"

	"github.com/busoc/rt"
	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
)

var (
	ModeRT = []byte("realtime")
	ModePB = []byte("playback")

	ChanVic1 = []byte("vic1")
	ChanVic2 = []byte("vic2")
	ChanLRSD = []byte("lrsd")

	Invalid = []byte("invalid")
	Unknown = []byte("***")
)

type Dumper struct {
	inner io.Writer
	line  *linewriter.Writer

	seen map[uint8]Packet
}

func Dump(w io.Writer, csv bool) *Dumper {
	var options []linewriter.Option
	if csv {
		options = append(options, linewriter.AsCSV(false))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	return &Dumper{
		inner: w,
		line:  linewriter.NewWriter(4096, options...),
		seen:  make(map[uint8]Packet),
	}
}

func (d *Dumper) DumpRaw(body []byte) {
	var offset int
	if w := binary.BigEndian.Uint32(body); w != Syncword {
		offset += HRDPHeaderLen
	}
	d.line.AppendBytes(body[offset:offset+8], 0, 0)
	d.line.AppendBytes(body[offset+8:offset+24], 0, 0)
	d.line.AppendBytes(body[offset+24:offset+48], 0, 0)
}

func (d *Dumper) Dump(body []byte, invalid, raw bool) error {
	var (
		err error
		p   Packet
	)
	if raw {
		d.DumpRaw(body)
	} else {
		p, err = DecodePacket(body, false)
		if err == nil || (err == ErrInvalid && invalid) {
			d.dumpPacket(p, err != ErrInvalid)
			d.seen[p.VMUHeader.Channel] = p

		}
	}
	if err == nil || err == ErrInvalid {
		io.Copy(d.inner, d.line)
	}
	return err
}

func (d *Dumper) dumpPacket(p Packet, valid bool) {
	var bad []byte
	if !valid {
		bad = Invalid
	} else {
		bad = Unknown
	}
	h, v, c := p.HRDPHeader, p.VMUHeader, p.DataHeader

	var diff int
	if other, ok := d.seen[v.Channel]; ok {
		diff = int(p.Missing(other))
	}

	// d.line.AppendBytes(WhichChannel(v.Channel), 4, linewriter.AlignCenter|linewriter.Text)
	d.line.AppendUint(uint64(v.Size), 7, linewriter.AlignRight)
	d.line.AppendUint(uint64(h.Error), 4, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	// packet VMU info
	d.line.AppendTime(v.Timestamp(), rt.TimeFormat, linewriter.AlignCenter)
	d.line.AppendUint(uint64(v.Sequence), 7, linewriter.AlignRight)
	d.line.AppendUint(uint64(diff), 5, linewriter.AlignRight)
	d.line.AppendBytes(WhichMode(p.IsRealtime()), 8, linewriter.AlignCenter|linewriter.Text)
	d.line.AppendBytes(WhichChannel(v.Channel), 4, linewriter.AlignCenter|linewriter.Text)
	// packet HRD info
	d.line.AppendUint(uint64(c.Origin), 2, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	d.line.AppendTime(c.Acquisition(), rt.TimeFormat, linewriter.AlignCenter)
	d.line.AppendUint(uint64(c.Counter), 8, linewriter.AlignRight)
	d.line.AppendBytes(c.UserInfo(), 14, linewriter.AlignLeft|linewriter.Text)
	d.line.AppendString(p.DataType(), 6, linewriter.AlignRight)
	// d.line.AppendString(p.String(), 64, linewriter.AlignLeft)
	// packet sums and validity state
	d.line.AppendUint(uint64(p.Sum), 8, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	d.line.AppendBytes(bad, 7, linewriter.AlignCenter|linewriter.Text)
	if len(p.Data) > 0 {
		d.line.AppendUint(xxh.Sum64(p.Data, 0), 16, linewriter.AlignRight|linewriter.Hex|linewriter.WithZero)
	}
}

func WhichChannel(c uint8) []byte {
	switch c {
	case VIC1:
		return ChanVic1
	case VIC2:
		return ChanVic2
	case LRSD:
		return ChanLRSD
	default:
		return Unknown
	}
}

func WhichMode(rt bool) []byte {
	if rt {
		return ModeRT
	}
	return ModePB
}
