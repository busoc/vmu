package main

import (
	"log"

	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
)

var commands = []*cli.Command{
	{
		Usage: "list [-e with-errors] [-c csv] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff [-e with-errors] [-b by] [-c csv] [-d duration] <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count [-e with-errors] [-b by] [-c csv] <file...>",
		Short: "",
		Run:   runCount,
	},
	{
		Usage: "take [-e with-errors] [-i channel] [-d datadir] <file...>",
		Short: "",
		Run:   runTake,
	},
	{
		Usage: "merge <final> <file...>",
		Short: "merge and reorder packets from multiple files",
		Run:   runMerge,
	},
	{
		Usage: "extract [-d datadir] [-e with-errors] [-c channel] <file...>",
		Short: "",
		Run:   nil,
	},
}

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("vmucat", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}

func Line(csv bool) *linewriter.Writer {
	var options []linewriter.Option
	if csv {
		options = append(options, linewriter.AsCSV(true))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	return linewriter.NewWriter(1024, options...)
}
