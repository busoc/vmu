package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/busoc/rt"
	"github.com/busoc/vmu"
	"github.com/midbel/cli"
	"github.com/midbel/roll"
)

func runMerge(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	files := cmd.Flag.Args()
	w, err := os.Create(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer w.Close()

	cmp := func(o, other rt.Offset) bool {
		if o.Time.Equal(other.Time) {
			if o.Pid != other.Pid {
				return o.Len < other.Len
			}
			return o.Sequence < other.Sequence
		}
		return o.Time.Before(other.Time)
	}

	return rt.MergeFiles(files[1:], w, func(bs []byte) (rt.Offset, error) {
		var o rt.Offset
		if len(bs) < vmu.HRDPHeaderLen+vmu.VMUHeaderLen {
			return o, rt.ErrSkip
		}
		v, err := vmu.DecodeVMU(bs[vmu.HRDPHeaderLen:])
		if err != nil {
			return o, err
		}
		o.Cmp = cmp

		o.Pid = uint(v.Channel)
		o.Sequence = uint(v.Sequence)
		o.Len = uint(v.Size)
		o.Time = v.Timestamp()

		return o, nil
	})
}

func runTake(cmd *cli.Command, args []string) error {
	var t taker

	cmd.Flag.DurationVar(&t.Interval, "d", 0, "")
	cmd.Flag.StringVar(&t.Prefix, "n", "", "")
	cmd.Flag.IntVar(&t.Channel, "i", 0, "apid")
	cmd.Flag.IntVar(&t.Size, "s", 0, "size")
	cmd.Flag.IntVar(&t.Count, "c", 0, "count")
	cmd.Flag.BoolVar(&t.Invalid, "e", false, "invalid")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}

	err := t.Sort(cmd.Flag.Arg(0), dirs)
	if err == nil {
		fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", t.state.Count, t.state.Skipped, t.state.Size>>10)
	}
	return err
}

type taker struct {
	Interval time.Duration
	Prefix   string
	Channel  int
	Size     int
	Count    int
	Invalid  bool

	state struct {
		Count   int
		Skipped int
		Size    int
		Stamp   time.Time
	}
}

func (t *taker) Sort(datadir string, dirs []string) error {
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	wc, err := roll.Roll(t.Open(datadir), roll.WithThreshold(t.Size, t.Count))
	if err != nil {
		return err
	}
	defer wc.Close()

	d := vmu.NewDecoder(rt.NewReader(mr), vmu.WithChannel(t.Channel, !t.Invalid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if t.Interval >= rt.Five {
				w := p.Timestamp()
				if !t.state.Stamp.IsZero() && w.Sub(t.state.Stamp) >= t.Interval {
					wc.Rotate()
				}
				if t.state.Stamp.IsZero() || w.Sub(t.state.Stamp) >= t.Interval {
					t.state.Stamp = w
				}
			}
			if buf, err := p.Marshal(); err == nil {
				if n, err := wc.Write(buf); err != nil {
					t.state.Skipped++
				} else {
					t.state.Size += n
					t.state.Count++
				}
			} else {
				t.state.Skipped++
			}
		case vmu.ErrSkip:
			t.state.Skipped++
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

func (t *taker) Open(dir string) roll.NextFunc {
	if t.Prefix == "" {
		if t.Channel != 0 {
			t.Prefix = string(vmu.WhichChannel(uint8(t.Channel)))
		} else {
			t.Prefix = "rt"
		}
	} else {
		t.Prefix = strings.TrimRight(t.Prefix, "_-")
	}
	return func(i int, w time.Time) (io.WriteCloser, []io.Closer, error) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, err
		}
		file := fmt.Sprintf("%s_%06d_%s.dat", t.Prefix, i-1, w.Format("20060102_150405"))
		wc, err := os.Create(filepath.Join(dir, file))
		return wc, nil, err
	}
}
