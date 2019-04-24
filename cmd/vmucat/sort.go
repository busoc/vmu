package main

import (
	"os"

	"github.com/busoc/rt"
	"github.com/busoc/vmu"
	"github.com/midbel/cli"
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
	return nil
}
