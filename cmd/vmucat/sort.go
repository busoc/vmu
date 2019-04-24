package main

import (
  "io"
  "os"
  "path/filepath"
  "fmt"
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
    if len(bs) < vmu.HRDPHeaderLen + vmu.VMUHeaderLen {
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
  pid := cmd.Flag.Int("i", 0, "channel")
  keepInvalid := cmd.Flag.Bool("e", false, "keep invalid packets")
  count := cmd.Flag.Int("c", 0, "count")
  size := cmd.Flag.Int("s", 0, "count")
  if err := cmd.Flag.Parse(args); err != nil {
    return err
  }
	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}

	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

  wc, err := roll.Roll(Open(cmd.Flag.Arg(0)), roll.WithThreshold(*size, *count))
  if err != nil {
    return err
  }
  defer wc.Close()

  d := vmu.NewDecoder(rt.NewReader(mr), vmu.WithChannel(*pid, !*keepInvalid))

  c := struct {
		Count   int
		Skipped int
		Size    int
  }{}
  for {
    switch p, err := d.Decode(true); err {
    case nil:
      if buf, err := p.Marshal(); err == nil {
        if n, err := wc.Write(buf); err == nil {
          c.Count++
          c.Size += n
        } else {
          c.Skipped++
        }
      } else {
        c.Skipped++
      }
    case vmu.ErrSkip:
      c.Skipped++
    case io.EOF:
      fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", c.Count, c.Skipped, c.Size>>10)
      return nil
    default:
      return err
    }
  }
}

func Open(datadir string) roll.NextFunc {
  return func(i int, w time.Time) (io.WriteCloser, []io.Closer, error) {
		if err := os.MkdirAll(datadir, 0755); err != nil {
			return nil, nil, err
		}
		file := fmt.Sprintf("rt_%06d_%s.dat", i-1, w.Format("20060102_150405"))
		wc, err := os.Create(filepath.Join(datadir, file))
		return wc, nil, err
  }
}
