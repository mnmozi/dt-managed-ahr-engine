// Command dt-engine reads a bundle directory produced by
// dt-managed-ahr-collector and emits structured findings.
//
// Usage:
//
//	dt-engine assess --bundle <dir> [--out findings.json]
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

	"github.com/local/dt-managed-engine/internal/bundle"
	"github.com/local/dt-managed-engine/internal/elog"
	"github.com/local/dt-managed-engine/internal/mcpserver"
	"github.com/local/dt-managed-engine/internal/runner"
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
	case "mcp":
		runMcp(os.Args[2:])
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

// runMcp starts an MCP server over stdio. Typically spawned by the data MCP
// (dt-managed-mcp) as a child process; humans usually don't invoke this
// directly. We initialize the structured logger so the parent can parse
// our stderr as JSONL.
func runMcp(_ []string) {
	elog.Init()
	log := elog.Source("lifecycle")
	log.Info("starting MCP server", "transport", "stdio", "engineVersion", version)
	srv := mcpserver.New("dt-engine", version)
	mcpserver.RegisterEngineTools(srv, version)
	if err := srv.Run(); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dt-engine — deterministic check engine for Dynatrace Managed

Subcommands:
  assess     run all checks against a bundle directory (CLI / offline mode)
  mcp        run as a stdio MCP server (called by dt-managed-mcp)
  version    print engine version
  help       show this help

assess flags:
  --bundle PATH     bundle directory (required)
  --out PATH        output path for findings.json (default: stdout)
  --pretty          pretty-print JSON output (default: true)

mcp:
  Reads MCP JSON-RPC over stdin, writes responses to stdout. Exposes
  engine_list_checks and engine_run tools. Typically spawned by the
  data MCP — humans don't usually invoke this directly.

Examples:
  dt-engine assess --bundle ./reports/acme/2026-04-30 --out findings.json
  dt-engine mcp     # (spawned by dt-managed-mcp)
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
	// CLI consumer sorts for human reading. The runner doesn't sort —
	// presentation is the consumer's job.
	runner.SortBySeverity(result.Findings)

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
		"[dt-engine] checks=%d findings=%d (high=%d medium=%d low=%d info=%d) bundle=%s\n",
		result.Engine.ChecksApplied,
		result.Counts.Total, result.Counts.High, result.Counts.Medium,
		result.Counts.Low, result.Counts.Info,
		result.BundleRoot,
	)
}
