// Program citron is the citron MCP server.  It exposes the citron safety
// harness as MCP tools, allowing AI agents to write and execute Starlark code
// through citron's capability-safe framework.
//
// The server follows the code-execution-with-MCP pattern: instead of loading
// dozens of tool definitions into context, the agent discovers the harness
// guide (via the harness_guide tool or the citron://harness-guide.md
// resource) and writes Starlark code using citron's tracked capabilities (fs,
// net, proc, io, Classified).
//
// Usage:
//
//	# Stdio transport (default — pipe into your MCP client)
//	go run ./cmd/citron
//
//	# Streamable HTTP transport
//	PORT=9090 go run ./cmd/citron
//
// Environment variables:
//
//	PORT                          HTTP port (default "8080", set empty for stdio)
//	CITRON_COMMAND_ALLOWLIST      Comma-separated allowed commands
//	CITRON_NETWORK_ALLOWLIST      Comma-separated allowed hosts
//	CITRON_CLASSIFIED_PATTERNS    Comma-separated classified glob patterns
//	CITRON_SECURE_OUTPUT_PATH     Path for unmasked classified output
//	CITRON_TIMEOUT_MS             Execution timeout in milliseconds (default 30000)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/mishudark/citron"
	"github.com/mishudark/citron/analysis"
	"github.com/mishudark/citron/mcpclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- MCP tool types ---

type ExecuteStarlarkParams struct {
	Code       string `json:"code" jsonschema:"The Starlark code to execute"`
	WorkingDir string `json:"workingDir,omitempty" jsonschema:"Optional virtual working directory"`
}

type ExecuteStarlarkResult struct {
	Output   string `json:"output" jsonschema:"The output from io.println calls"`
	Duration int64  `json:"durationMs" jsonschema:"Execution time in milliseconds"`
}

type AnalyzeStarlarkParams struct {
	Code string `json:"code" jsonschema:"The Starlark code to analyze for safety violations"`
}

type AnalyzeStarlarkResult struct {
	Valid  bool           `json:"valid"`
	Issues []AnalyzeIssue `json:"issues,omitempty"`
}

type AnalyzeIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    int    `json:"line"`
}

type CapabilitiesResult struct {
	Capabilities []mcpclient.CapabilityInfo `json:"capabilities"`
}

type HarnessGuideResult struct {
	Guide string `json:"guide"`
}

func getEnvSlice(key string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}

func getEnvInt(key string, def int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	return def
}

func main() {
	port := os.Getenv("PORT")

	opts := citron.Options{
		CommandAllowlist:   getEnvSlice("CITRON_COMMAND_ALLOWLIST"),
		NetworkAllowlist:   getEnvSlice("CITRON_NETWORK_ALLOWLIST"),
		ClassifiedPatterns: getEnvSlice("CITRON_CLASSIFIED_PATTERNS"),
		SecureOutputPath:   os.Getenv("CITRON_SECURE_OUTPUT_PATH"),
		TimeoutMs:          getEnvInt("CITRON_TIMEOUT_MS", 30000),
	}

	server := NewServer(opts)

	// Determine transport: stdio or HTTP.
	if port == "" {
		log.Print("citron-mcp-server running on stdio")
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatalf("stdio run: %v", err)
		}
		return
	}

	log.Printf("citron-mcp-server listening on :%s (streamable HTTP)", port)
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("http serve: %v", err)
	}
}

// NewServer creates an MCP server with all citron tools registered.
// remoteCaps are optional capabilities from generated RegisterRemoteTools
// that get appended to the list_capabilities response.
// It is exported for testing.
func NewServer(opts citron.Options, remoteCaps ...mcpclient.CapabilityInfo) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "citron-mcp-server",
		Version: "1.0.0",
	}, &mcp.ServerOptions{
		Instructions: "citron is a safety harness for AI agents. " +
			"Write Starlark (Python) code using `fs`, `net`, `proc`, and `io` globals. " +
			"Call `harness_guide` first to learn the API.",
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "execute_starlark",
		Description: "Execute a Starlark code snippet within the citron safety harness. The code runs in an isolated sandbox with access to fs, net, proc, and io capabilities. Static analysis enforces Classified purity and rejects dangerous code before execution.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params ExecuteStarlarkParams) (*mcp.CallToolResult, ExecuteStarlarkResult, error) {
		execOpts := opts
		if params.WorkingDir != "" {
			execOpts.WorkingDir = params.WorkingDir
		} else {
			cwd, _ := os.Getwd()
			execOpts.WorkingDir = cwd
		}

		res, err := citron.SafeExecute(params.Code, execOpts)
		if err != nil {
			return nil, ExecuteStarlarkResult{}, fmt.Errorf("execution failed: %w", err)
		}
		return nil, ExecuteStarlarkResult{Output: res.Output, Duration: res.Duration}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_starlark",
		Description: "Run the static analyzer on a Starlark code snippet without executing it. Returns structured results listing each safety issue found (impure callbacks, Classified write mismatches, etc.).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params AnalyzeStarlarkParams) (*mcp.CallToolResult, AnalyzeStarlarkResult, error) {
		issues, err := analysis.Analyze("agent.star", []byte(params.Code))
		if err != nil {
			return nil, AnalyzeStarlarkResult{}, fmt.Errorf("analysis error: %w", err)
		}
		if len(issues) == 0 {
			return nil, AnalyzeStarlarkResult{Valid: true}, nil
		}
		result := AnalyzeStarlarkResult{Valid: false}
		for _, iss := range issues {
			result.Issues = append(result.Issues, AnalyzeIssue{
				Code:    iss.Code,
				Message: iss.Message,
				Line:    int(iss.Pos.Line),
			})
		}
		return nil, result, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "harness_guide",
		Description: "Returns the citron HARNESS_GUIDE.md. Call this first to learn how to write Starlark code with the harness (capabilities, classified data, etc.).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, HarnessGuideResult, error) {
		return nil, HarnessGuideResult{Guide: citron.HarnessGuide}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_capabilities",
		Description: "Lists all citron capabilities available in the Starlark execution environment (fs, net, proc, io) with their methods and usage examples.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, CapabilitiesResult, error) {
		caps := []mcpclient.CapabilityInfo{
			{
				Name:        "FileSystem",
				Description: "Access to a virtual in-memory filesystem. All paths relative to the working directory. Supports classified and unclassified reads/writes.",
				Globals:     "fs",
				Methods:     "fs.access(path) -> FileEntry\n  entry.read() -> string\n  entry.write(content)\n  entry.read_classified() -> Classified\n  entry.write_classified(data)",
				Example:     "f = fs.access(\"hello.txt\")\nf.write(\"hello from citron!\")\nio.println(f.read())",
			},
			{
				Name:        "Network",
				Description: "HTTP GET requests to allowlisted hosts. Redirect targets are re-validated against the allowlist.",
				Globals:     "net",
				Methods:     "net.get(url) -> string",
				Example:     "body = net.get(\"https://api.example.com/v1/status\")\nio.println(body)",
			},
			{
				Name:        "Process",
				Description: "Execute commands on the host system. Only allowlisted commands are permitted.",
				Globals:     "proc",
				Methods:     "proc.exec(cmd, args) -> string (stdout)",
				Example:     `out = proc.exec("echo", ["hello world"])` + "\n" + `io.println(out)`,
			},
			{
				Name:        "IO",
				Description: "Gate for all agent-visible output. Classified values are masked as 'Classified(****)'. A secure output sink receives the real value.",
				Globals:     "io (also available as print())",
				Methods:     "io.println(...)",
				Example:     `io.println("agent sees this")`,
			},
			{
				Name:        "Classified",
				Description: "Wraps sensitive values to prevent exfiltration. Supports pure transformations via map/flat_map. The static analyzer rejects impure callbacks (io.println, fs.access, etc. inside map).",
				Globals:     "Classified (returned by read_classified())",
				Methods:     "classified.map(callback) -> Classified\nclassified.flat_map(callback) -> Classified",
				Example:     `secret = fs.access("key.txt").read_classified()` + "\n" + `def to_upper(s): return s.upper()` + "\n" + `upper = secret.map(to_upper)` + "\n" + `io.println(upper)  # Classified(****)`,
			},
		}
		caps = append(caps, remoteCaps...)
		return nil, CapabilitiesResult{Capabilities: caps}, nil
	})

	// Add the harness guide as a readable resource (in addition to the tool).
	server.AddResource(&mcp.Resource{
		Name:        "Harness Guide",
		URI:         "citron://harness-guide.md",
		Description: "Instructions for generating safe Starlark code for the citron harness.",
		MIMEType:    "text/markdown",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				Text:     citron.HarnessGuide,
				MIMEType: "text/markdown",
				URI:      "citron://harness-guide.md",
			}},
		}, nil
	})

	return server
}
