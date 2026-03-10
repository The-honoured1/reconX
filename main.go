package main

import (
	"flag"
	"fmt"
	"os"
	"reconx/engine"
	"reconx/ui"
)

func main() {
	target := flag.String("t", "", "Target domain (e.g., example.com)")
	flag.Parse()

	if *target == "" {
		if len(os.Args) > 1 && os.Args[1] != "" && os.Args[1][0] != '-' {
			*target = os.Args[1]
		} else {
			fmt.Println("Usage: reconx <domain> or reconx -t <domain>")
			os.Exit(1)
		}
	}

	appEngine := engine.NewEngine(*target)
	if err := ui.Run(appEngine); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
