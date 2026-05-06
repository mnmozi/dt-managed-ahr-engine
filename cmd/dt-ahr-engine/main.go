// Command dt-ahr-engine reads a bundle directory produced by
// dt-managed-ahr-collector and emits structured findings.
//
// Usage:
//
//	dt-ahr-engine assess --bundle <dir> [--out findings.json]
//
// The engine never touches Dynatrace directly — bundles are produced by
// the separate collector, which keeps this binary a pure, offline,
// reproducible function from bundle to findings.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/local/dt-managed-ahr-engine/internal/bundle"
	"github.com/local/dt-managed-ahr-engine/internal/runner"
)

const version = "0.0.1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "assess":
		runAssess(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dt-ahr-engine — deterministic AHR check engine

Subcommands:
  assess     run all checks against a collector bundle
  version    print engine version
  help       show this help

assess flags:
  --bundle PATH     bundle directory produced by dt-managed-ahr-collector (required)
  --out PATH        output path for findings.json (default: stdout)
  --pretty          pretty-print JSON output (default: true)

Example:
  dt-ahr-engine assess --bundle ./reports/acme/2026-04-30 --out findings.json
`)
}

func runAssess(args []string) {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "bundle directory (required)")
	outPath := fs.String("out", "", "output file path; empty = stdout")
	pretty := fs.Bool("pretty", true, "pretty-print JSON")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "--bundle is required")
		fs.Usage()
		os.Exit(2)
	}

	b, err := bundle.Load(*bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load bundle: %v\n", err)
		os.Exit(1)
	}

	result := runner.Run(b, version)

	w := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", *outPath, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}

	// Tiny human-friendly summary on stderr so the user sees something even
	// when they piped JSON to a file.
	fmt.Fprintf(os.Stderr,
		"[dt-ahr-engine] checks=%d findings=%d (high=%d medium=%d low=%d info=%d) bundle=%s\n",
		result.Engine.ChecksApplied,
		result.Counts.Total, result.Counts.High, result.Counts.Medium,
		result.Counts.Low, result.Counts.Info,
		result.BundleRoot,
	)
}
