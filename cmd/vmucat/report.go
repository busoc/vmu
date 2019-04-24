package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/busoc/rt"
	"github.com/busoc/vmu"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
)

func runList(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	keepInvalid := cmd.Flag.Bool("e", false, "keep invalid packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	rt := rt.NewReader(mr)
	d := vmu.Dump(os.Stdout, *csv)

	c := struct {
		Invalid int
		Size    int
		Skipped int
		Count   int
	}{}
	buffer := make([]byte, vmu.BufferSize)
	for i := 0; ; i++ {
		switch n, err := rt.Read(buffer); err {
		case nil:
			c.Size += n
			if err := d.Dump(buffer[:n], *keepInvalid, false); err != nil {
				if err == vmu.ErrInvalid {
					c.Invalid++
				} else if err == vmu.ErrSkip {
					c.Skipped++
				} else {
					return err
				}
			}
			c.Count++
		case io.EOF:
			log.Printf("%d packets (%dMB, %d invalid, %d skipped)\n", c.Count, c.Size>>20, c.Invalid, c.Skipped)
			return nil
		default:
			return err
		}
	}
}
func runCount(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	keepInvalid := cmd.Flag.Bool("e", false, "keep invalid packets")
	by := cmd.Flag.String("b", "", "count packets by channel or origin")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		getBy    func(vmu.Packet) uint8
		missBy   func(vmu.Packet, vmu.Packet) uint64
		appendBy func(*linewriter.Writer, uint8)
	)
	switch strings.ToLower(*by) {
	case "channel", "":
		getBy = byChannel
		missBy = func(p, prev vmu.Packet) uint64 {
			if p.VMUHeader.Sequence < prev.VMUHeader.Sequence {
				return 0
			}
			return uint64(p.VMUHeader.Sequence-prev.VMUHeader.Sequence) - 1
		}
		appendBy = func(line *linewriter.Writer, c uint8) {
			line.AppendBytes(vmu.WhichChannel(c), 4, linewriter.Text|linewriter.AlignLeft)
		}
	case "origin":
		getBy = byOrigin
		missBy = func(p, prev vmu.Packet) uint64 {
			if p.DataHeader.Counter < prev.DataHeader.Counter {
				return 0
			}
			return uint64(p.DataHeader.Counter-prev.DataHeader.Counter) - 1
		}
		appendBy = func(line *linewriter.Writer, c uint8) {
			line.AppendUint(uint64(c), 2, linewriter.AlignCenter|linewriter.Hex|linewriter.WithZero)
		}
	default:
		return fmt.Errorf("unknown value %s", *by)
	}

	d, err := Decode(cmd.Flag.Args())
	if err != nil {
		return err
	}
	stats := make(map[uint8]rt.Coze)
	seen := make(map[uint8]vmu.Packet)
	for {
		switch p, err := d.Decode(false); err {
		case nil, vmu.ErrInvalid:
			by := getBy(p)
			cz := stats[by]

			cz.Count++
			cz.Size += uint64(p.VMUHeader.Size)
			if err == vmu.ErrInvalid {
				cz.Error++
				if !*keepInvalid {
					continue
				}
			}
			if prev, ok := seen[by]; ok {
				cz.Missing += missBy(p, prev)
			}
			seen[by], stats[by] = p, cz
		case vmu.ErrSkip:
		case io.EOF:
			line := Line(*csv)
			for b, cz := range stats {
				appendBy(line, b)
				line.AppendUint(cz.Count, 6, linewriter.AlignRight)
				line.AppendUint(cz.Missing, 6, linewriter.AlignRight)
				line.AppendUint(cz.Error, 6, linewriter.AlignRight)
				line.AppendUint(cz.Size, 6, linewriter.AlignRight)
				io.Copy(os.Stdout, line)
			}
			return nil
		default:
			return err
		}
	}
}

func runDiff(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	keepInvalid := cmd.Flag.Bool("e", false, "keep invalid packets")
	by := cmd.Flag.String("b", "", "count packets by channel or origin")
	duration := cmd.Flag.Duration("d", time.Second, "maximum gap duration")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var (
		getBy    func(vmu.Packet) uint8
		gapBy    func(vmu.Packet, vmu.Packet, time.Duration) (bool, rt.Gap)
		appendBy func(*linewriter.Writer, vmu.Packet)
	)
	switch strings.ToLower(*by) {
	case "channel", "":
		getBy = byChannel
		gapBy = gapByChannel
		appendBy = func(line *linewriter.Writer, p vmu.Packet) {
			line.AppendBytes(vmu.WhichChannel(p.VMUHeader.Channel), 4, linewriter.Text|linewriter.AlignLeft)
		}
	case "origin":
		getBy = byOrigin
		gapBy = gapByOrigin
		appendBy = func(line *linewriter.Writer, p vmu.Packet) {
			line.AppendBytes(vmu.WhichChannel(p.VMUHeader.Channel), 4, linewriter.Text|linewriter.AlignLeft)
			line.AppendUint(uint64(p.DataHeader.Origin), 2, linewriter.AlignCenter|linewriter.Hex|linewriter.WithZero)
		}
	default:
		return fmt.Errorf("unknown value %s", *by)
	}

	d, err := Decode(cmd.Flag.Args())
	if err != nil {
		return err
	}
	seen := make(map[uint8]vmu.Packet)
	line := Line(*csv)
	for {
		switch p, err := d.Decode(false); err {
		case nil, vmu.ErrInvalid:
			if err == vmu.ErrInvalid && !*keepInvalid {
				continue
			}
			by := getBy(p)
			if prev, ok := seen[by]; ok {
				if ok, g := gapBy(p, prev, *duration); ok {
					appendBy(line, p)
					line.AppendTime(g.Starts, rt.TimeFormat, linewriter.AlignRight)
					line.AppendTime(g.Ends, rt.TimeFormat, linewriter.AlignRight)
					line.AppendInt(int64(g.Last), 8, linewriter.AlignRight)
					line.AppendInt(int64(g.First), 8, linewriter.AlignRight)
					line.AppendInt(int64(g.Missing()), 8, linewriter.AlignRight)
					line.AppendDuration(g.Duration(), 10, linewriter.AlignRight)

					io.Copy(os.Stdout, line)
				}
			}
			seen[by] = p
		case vmu.ErrSkip:
		case io.EOF:
			return nil
		default:
			return err
		}
	}
	return nil
}

func Decode(files []string) (*vmu.Decoder, error) {
	mr, err := rt.Browse(files, true)
	if err != nil {
		return nil, err
	}
	return vmu.NewDecoder(rt.NewReader(mr), nil), nil
}

func byChannel(p vmu.Packet) uint8 {
	return p.VMUHeader.Channel
}

func byOrigin(p vmu.Packet) uint8 {
	return p.DataHeader.Origin
}

func gapByChannel(p, prev vmu.Packet, duration time.Duration) (ok bool, g rt.Gap) {
	last, first := int(p.VMUHeader.Sequence), int(prev.VMUHeader.Sequence)
	delta := p.VMUHeader.Timestamp().Sub(prev.VMUHeader.Timestamp())

	if diff := last - first; diff != 1 && (duration == 0 || delta <= duration) {
		g.Last = first
		g.First = last
		g.Starts = prev.VMUHeader.Timestamp()
		g.Ends = p.VMUHeader.Timestamp()

		ok = true
	}
	return
}

func gapByOrigin(p, prev vmu.Packet, duration time.Duration) (ok bool, g rt.Gap) {
	last, first := int(p.DataHeader.Counter), int(prev.DataHeader.Counter)
	delta := p.DataHeader.Acquisition().Sub(prev.DataHeader.Acquisition())

	if diff := last - first; diff != 1 && (duration == 0 || delta <= duration) {
		g.Last = first
		g.First = last
		g.Starts = prev.DataHeader.Acquisition()
		g.Ends = p.DataHeader.Acquisition()

		ok = true
	}
	return
}
