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

const (
	Channel = "channel"
	Origin  = "origin"
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
	interval := cmd.Flag.Duration("i", 0, "interval")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()

	stats, err := countPackets(rt.NewReader(mr), strings.ToLower(*by), !*keepInvalid, *interval)
	if err != nil {
		return err
	}
	line := Line(*csv)
	for k, cz := range stats {
		line.AppendBytes(vmu.WhichChannel(k.Channel), 4, linewriter.Text|linewriter.AlignLeft)
		if strings.ToLower(*by) == Origin {
			line.AppendUint(uint64(k.Origin), 2, linewriter.AlignCenter|linewriter.Hex|linewriter.WithZero)
		}
		line.AppendUint(cz.Count, 6, linewriter.AlignRight)
		line.AppendUint(cz.Missing, 6, linewriter.AlignRight)
		line.AppendUint(cz.Error, 6, linewriter.AlignRight)
		if *csv {
			line.AppendUint(cz.Size, 8, linewriter.AlignRight)
		} else {
			line.AppendSize(int64(cz.Size), 8, linewriter.AlignRight)
		}
		line.AppendUint(cz.First, 8, linewriter.AlignRight)
		line.AppendTime(cz.StartTime, rt.TimeFormat, linewriter.AlignRight)
		line.AppendUint(cz.Last, 8, linewriter.AlignRight)
		line.AppendTime(cz.EndTime, rt.TimeFormat, linewriter.AlignRight)
		io.Copy(os.Stdout, line)
	}
	return nil
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
		getBy func(vmu.Packet, time.Duration) key
		gapBy func(vmu.Packet, vmu.Packet, time.Duration) (bool, rt.Gap)
	)

	switch strings.ToLower(*by) {
	case Channel, "":
		getBy = byChannel
		gapBy = gapByChannel
	case Origin:
		getBy = byOrigin
		gapBy = gapByOrigin
	default:
		return fmt.Errorf("unknown value %s", *by)
	}

	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()

	d := vmu.NewDecoder(rt.NewReader(mr), nil)

	seen := make(map[key]vmu.Packet)
	line := Line(*csv)
	for {
		switch p, err := d.Decode(false); err {
		case nil, vmu.ErrInvalid:
			if err == vmu.ErrInvalid && !*keepInvalid {
				continue
			}
			k := getBy(p, 0)
			if prev, ok := seen[k]; ok {
				if ok, g := gapBy(p, prev, *duration); ok {
					line.AppendBytes(vmu.WhichChannel(p.VMUHeader.Channel), 4, linewriter.Text|linewriter.AlignLeft)
					if strings.ToLower(*by) == "origin" {
						line.AppendUint(uint64(p.DataHeader.Origin), 2, linewriter.AlignCenter|linewriter.Hex|linewriter.WithZero)
					}
					line.AppendTime(g.Starts, rt.TimeFormat, linewriter.AlignRight)
					line.AppendTime(g.Ends, rt.TimeFormat, linewriter.AlignRight)
					line.AppendInt(int64(g.Last), 8, linewriter.AlignRight)
					line.AppendInt(int64(g.First), 8, linewriter.AlignRight)
					line.AppendInt(int64(g.Missing()), 8, linewriter.AlignRight)
					line.AppendDuration(g.Duration(), 10, linewriter.AlignRight)

					io.Copy(os.Stdout, line)
				}
			}
			seen[k] = p
		case vmu.ErrSkip:
		case io.EOF:
			return nil
		default:
			return err
		}
	}
	return nil
}

type key struct {
	Channel uint8
	Origin  uint8
	time.Time
}

func byChannel(p vmu.Packet, interval time.Duration) key {
	k := key{Channel: p.VMUHeader.Channel}
	if interval > 0 {
		k.Time = p.VMUHeader.Timestamp().Truncate(interval)
	}
	return k
}

func byOrigin(p vmu.Packet, interval time.Duration) key {
	k := byChannel(p, 0)
	k.Origin = p.DataHeader.Origin
	if interval > 0 {
		k.Time = p.DataHeader.Acquisition().Truncate(interval)
	}
	return k
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

func countPackets(r io.Reader, by string, invalid bool, interval time.Duration) (map[key]rt.Coze, error) {
	var (
		getBy  func(vmu.Packet, time.Duration) key
		missBy func(vmu.Packet, vmu.Packet) uint64
	)
	switch by {
	case Channel, "":
		getBy = byChannel
		missBy = func(p, prev vmu.Packet) uint64 {
			if p.VMUHeader.Sequence < prev.VMUHeader.Sequence {
				return 0
			}
			return uint64(p.VMUHeader.Sequence-prev.VMUHeader.Sequence) - 1
		}
	case Origin:
		getBy = byOrigin
		missBy = func(p, prev vmu.Packet) uint64 {
			if p.DataHeader.Counter < prev.DataHeader.Counter {
				return 0
			}
			return uint64(p.DataHeader.Counter-prev.DataHeader.Counter) - 1
		}
	default:
		return nil, fmt.Errorf("unknown value %s", by)
	}
	d := vmu.NewDecoder(r, nil)
	stats := make(map[key]rt.Coze)
	seen := make(map[key]vmu.Packet)
	for {
		p, err := d.Decode(false)
		switch err {
		case nil, vmu.ErrInvalid:
			by := getBy(p, interval)
			cz := stats[by]

			cz.Count++
			cz.Size += uint64(p.VMUHeader.Size)
			if err == vmu.ErrInvalid {
				cz.Error++
				if !invalid {
					continue
				}
			}
			cz.Last, cz.EndTime = uint64(p.Sequence), p.Timestamp()
			if cz.StartTime.IsZero() {
				cz.First, cz.StartTime = cz.Last, cz.EndTime
			}
			if prev, ok := seen[by]; ok {
				cz.Missing += missBy(p, prev)
			}
			seen[by], stats[by] = p, cz
		case vmu.ErrSkip:
		case io.EOF:
			return stats, nil
		default:
			return nil, err
		}
	}
}
