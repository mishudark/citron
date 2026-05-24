// Program mcpgen connects to a remote MCP server, lists its tools (with JSON
// Schema inputs and outputs), and generates a ready-to-compile Go file that
// wraps each tool as a Starlark builtin capability for the citron harness.
//
// Usage:
//
//	# Streamable HTTP transport
//	go run ./cmd/mcpgen --url http://localhost:9090/mcp --package mytools --output gen_mcp.go
//
//	# Stdio transport (spawn a subprocess)
//	go run ./cmd/mcpgen --command "npx @modelcontextprotocol/server-everything" --package tools
//
//	# SSE transport
//	go run ./cmd/mcpgen --sse http://localhost:8080/sse --package mytools
//
// The generated file exports a function RegisterMCPSession(*mcp.ClientSession) starlark.StringDict
// that can be merged into the citron execution context alongside fs, net, proc, and io.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mishudark/citron/mcpclient"
)

type config struct {
	serverURL string
	sseURL    string
	command   string
	pkgName   string
	funcName  string
	output    string
	tag       string
	dryRun    bool
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("mcpgen: ")

	cfg := parseFlags()

	// Determine transport and build Config.
	connCfg, err := buildConnConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Connect.
	session, err := mcpclient.Connect(ctx, connCfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("session close: %v", err)
		}
	}()

	// 2. List tools.
	tools, err := mcpclient.ListTools(ctx, session)
	if err != nil {
		log.Fatalf("list tools: %v", err)
	}

	if len(tools) == 0 {
		log.Print("server returned 0 tools; generated file will be an empty stub")
	}

	// 3. Generate Go code.
	code, err := mcpclient.GenerateTools(tools, mcpclient.GenOptions{
		PackageName: cfg.pkgName,
		FuncName:    cfg.funcName,
		Tag:         cfg.tag,
	})
	if err != nil {
		log.Fatalf("generate code: %v", err)
	}

	// 4. Write output.
	if cfg.dryRun {
		fmt.Print(string(code))
		return
	}

	if err := os.WriteFile(cfg.output, code, 0644); err != nil {
		log.Fatalf("write %s: %v", cfg.output, err)
	}

	log.Printf("wrote %s (%d tools, %d bytes)", cfg.output, len(tools), len(code))
}

func parseFlags() *config {
	var cfg config

	flag.StringVar(&cfg.serverURL, "url", "",
		"Remote MCP server URL (streamable HTTP transport)")
	flag.StringVar(&cfg.sseURL, "sse", "",
		"Remote MCP SSE endpoint URL (SSE transport)")
	flag.StringVar(&cfg.command, "command", "",
		"Subprocess command to spawn (stdio transport, e.g. \"npx @server/pkg\")")
	flag.StringVar(&cfg.pkgName, "package", "mcpgen",
		"Go package name for the generated file")
	flag.StringVar(&cfg.funcName, "func", "RegisterMCPSession",
		"Name of the generated registration function")
	flag.StringVar(&cfg.output, "output", "gen_mcp.go",
		"Output file path")
	flag.StringVar(&cfg.tag, "tag", "",
		"Optional Go build tag (e.g. \"mcp_local\")")
	flag.BoolVar(&cfg.dryRun, "dry-run", false,
		"Print generated code to stdout instead of writing to file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mcpgen [flags]

Connects to a remote MCP server, lists its tools, and generates a Go file
that wraps each tool as a Starlark builtin capability for the citron harness.

Exactly one of --url, --sse, or --command must be provided.

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  mcpgen --url http://localhost:9090/mcp --package mytools --output mcp_tools.go
  mcpgen --command "npx @modelcontextprotocol/server-everything" --package tools
  mcpgen --sse http://localhost:8080/sse --package mytools --dry-run
`)
	}

	flag.Parse()

	if cfg.serverURL == "" && cfg.sseURL == "" && cfg.command == "" {
		log.Fatal("exactly one of --url, --sse, or --command is required")
	}
	n := 0
	for _, s := range []string{cfg.serverURL, cfg.sseURL, cfg.command} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		log.Fatal("only one of --url, --sse, or --command may be specified")
	}

	return &cfg
}

func buildConnConfig(cfg *config) (*mcpclient.Config, error) {
	switch {
	case cfg.serverURL != "":
		return &mcpclient.Config{
			Transport: mcpclient.TransportStreamableHTTP,
			ServerURL: cfg.serverURL,
			Timeout:   25 * time.Second,
		}, nil

	case cfg.sseURL != "":
		return &mcpclient.Config{
			Transport: mcpclient.TransportSSE,
			ServerURL: cfg.sseURL,
			Timeout:   25 * time.Second,
		}, nil

	case cfg.command != "":
		parts := strings.Fields(cfg.command)
		if len(parts) == 0 {
			return nil, errors.New("empty --command")
		}
		return &mcpclient.Config{
			Transport: mcpclient.TransportStdio,
			Command:   parts,
			Timeout:   25 * time.Second,
		}, nil

	default:
		return nil, errors.New("no transport specified")
	}
}
