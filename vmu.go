package vmu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
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

type ImageType uint8

const (
	Gray ImageType = iota + 1
	Gray16BE
	Gray16LE
	YUY2
	I420
	RGB
	JPEG
	PNG
	H264
)

func (i ImageType) String() string {
	switch i {
	default:
		return datExt
	case Gray:
		return "gray"
	case Gray16BE:
		return "gray16be"
	case Gray16LE:
		return "gray16le"
	case YUY2:
		return "yuy2"
	case I420:
		return "i420"
	case RGB:
		return "rgb"
	case JPEG:
		return "jpg"
	case PNG:
		return "png"
	case H264:
		return "h264"
	}
}

const (
	nameFormat     = "%04x_%s_%d_%06d_%s_%09d.%s"
	nameTimeFormat = "20060102_150405"
)

const (
	badExt = "bad"
	datExt = "dat"
)

const BufferSize = 8 << 20

type Packet struct {
	HRDPHeader
	VMUHeader
	DataHeader
	Data []byte
	Sum  uint32
}

func (p Packet) Export(w io.Writer, format string) error {
	switch p.VMUHeader.Channel {
	case VIC1, VIC2:
		return p.ExportImage(w, format)
	case LRSD:
		return fmt.Errorf("unrecognized data type")
	default:
		return fmt.Errorf("unrecognized data type")
	}
}

func (p Packet) ExportImage(w io.Writer, format string) error {
	// var i image.Image
	switch p.DataHeader.Type {
	default:
		return fmt.Errorf("unsupported image type")
	case Gray:
	case Gray16BE:
	case Gray16LE:
	case YUY2:
	case I420:
	case RGB:
	case JPEG:
		format = JPEG.String()
	case PNG:
		format = PNG.String()
	}
	switch format {
	case "", "png":
	case "jpg", "jpeg":
	default:
		return fmt.Errorf("unrecognized image format")
	}
	return nil
}

func (p Packet) DataType() string {
	if p.VMUHeader.Channel == LRSD {
		return datExt
	} else {
		return p.DataHeader.Type.String()
	}
}

func (p Packet) String() string {
	t := p.DataHeader.Acquisition().Format(nameTimeFormat)
	delta := p.VMUHeader.Timestamp().Sub(p.DataHeader.Acquisition()).Minutes()
	upi, ext := p.UserInfo(), datExt
	if len(upi) == 0 {
		if p.VMUHeader.Channel == LRSD {
			upi = upiScience
		} else {
			upi = upiImage
			ext = p.DataHeader.Type.String()
		}
	}
	return fmt.Sprintf(nameFormat, p.DataHeader.Origin, upi, p.VMUHeader.Channel, p.DataHeader.Counter, t, delta, ext)
}

func (p Packet) Filename() string {
	return p.String()
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

	// following fields are set only when Propery>>4 == 2 (Image)
	Type ImageType
	// original image size in pixels
	PixelsX uint16
	PixelsY uint16
	// region of interest settings
	OffsetX uint16
	SizeX   uint16
	OffsetY uint16
	SizeY   uint16

	Dropping uint16

	// scaling settings
	ScaleX uint16
	ScaleY uint16
	Ratio  uint8
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
		v.Type = ImageType(body[24])

		pixels := binary.LittleEndian.Uint32(body[25:])
		v.PixelsX = uint16(pixels >> 16)
		v.PixelsY = uint16(pixels & 0xFFFF)

		roi := binary.LittleEndian.Uint64(body[29:])
		v.OffsetX = uint16((roi >> 48) & 0xFFFF)
		v.SizeX = uint16((roi >> 32) & 0xFFFF)
		v.OffsetY = uint16(roi >> 16 & 0xFFFF)
		v.SizeY = uint16(roi & 0xFFFF)

		v.Dropping = binary.LittleEndian.Uint16(body[37:])

		scaling := binary.LittleEndian.Uint32(body[39:])
		v.ScaleX = uint16(scaling >> 16)
		v.ScaleY = uint16(scaling & 0xFFFF)
		v.Ratio = uint8(body[43])

		copy(v.UPI[:], body[44:])
	}
	return v, nil
}

func imageRGB(x, y int, points []byte) image.Image {
	g := image.NewRGBA(image.Rect(0, 0, x, y))
	buf := bytes.NewBuffer(points)
	for i := 0; i < y; i++ {
		for j := 0; j < x; j++ {
			var red, green, blue uint8
			binary.Read(buf, binary.BigEndian, &red)
			binary.Read(buf, binary.BigEndian, &green)
			binary.Read(buf, binary.BigEndian, &blue)

			g.Set(j, i, color.RGBA{R: red, G: green, B: blue, A: 255})
		}
	}
	return g
}

func imageLBR(x, y int, points []byte) image.Image {
	g := image.NewYCbCr(image.Rect(0, 0, x, y), image.YCbCrSubsampleRatio422)

	ls := make([]byte, 0, len(points)/2)
	bs := make([]byte, 0, len(points)/4)
	rs := make([]byte, 0, len(points)/4)

	for i := 0; i < len(points); i += 4 {
		ls = append(ls, points[i], points[i+2])
		bs = append(rs, points[i+1])
		rs = append(rs, points[i+3])
	}
	copy(g.Y, ls)
	copy(g.Cb, bs)
	copy(g.Cr, rs)

	return g
}

func imageI420(x, y int, points []byte) image.Image {
	g := image.NewYCbCr(image.Rect(0, 0, x, y), image.YCbCrSubsampleRatio420)

	s := x * y
	z := s / 4
	copy(g.Y, points[:s])

	copy(g.Cb, points[s:s+z])
	copy(g.Cr, points[len(points)-z:])

	return g
}

func imageGray8(x, y int, points []byte) image.Image {
	g := image.NewGray(image.Rect(0, 0, x, y))
	buf := bytes.NewBuffer(points)
	for i := 0; i < y; i++ {
		for j, c := range buf.Next(x) {
			g.Set(j, i, color.Gray{Y: uint8(c)})
		}
	}
	return g
}

func imageGray16(x, y int, points []byte, order binary.ByteOrder) image.Image {
	g := image.NewGray16(image.Rect(0, 0, x, y))
	buf := bytes.NewBuffer(points)
	for i := 0; i < y; i++ {
		for j := 0; j < x; j++ {
			var c uint16
			binary.Read(buf, order, &c)
			g.Set(j, i, color.Gray16{Y: c})
		}
	}
	return g
}
