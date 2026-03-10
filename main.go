package main

import (
	"flag"
	"fmt"
	"os"
	"reconx/engine"
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
	appEngine.Run()
}
