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
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ExecuteStarlarkParams struct {
	Code       string `json:"code" jsonschema:"The Starlark code to execute"`
	WorkingDir string `json:"workingDir,omitempty" jsonschema:"Optional directory to run the code in"`
}

type AnalyzeStarlarkParams struct {
	Code string `json:"code" jsonschema:"The Starlark code to analyze for safety violations"`
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
	if port == "" {
		port = "8080"
	}

	opts := citron.Options{
		CommandAllowlist:   getEnvSlice("CITRON_COMMAND_ALLOWLIST"),
		NetworkAllowlist:   getEnvSlice("CITRON_NETWORK_ALLOWLIST"),
		ClassifiedPatterns: getEnvSlice("CITRON_CLASSIFIED_PATTERNS"),
		SecureOutputPath:   os.Getenv("CITRON_SECURE_OUTPUT_PATH"),
		TimeoutMs:          getEnvInt("CITRON_TIMEOUT_MS", 30000),
	}

	// Create an MCP server.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "citron-mcp-server",
		Version: "1.0.0",
	}, nil)

	// Add the execute_starlark tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "execute_starlark",
		Description: "Execute a Starlark code snippet within the citron safety harness.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params *ExecuteStarlarkParams) (*mcp.CallToolResult, any, error) {
		execOpts := opts
		if params.WorkingDir != "" {
			execOpts.WorkingDir = params.WorkingDir
		} else {
			cwd, _ := os.Getwd()
			execOpts.WorkingDir = cwd
		}

		res, err := citron.SafeExecute(params.Code, execOpts)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)},
				},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: res.Output},
			},
		}, nil, nil
	})

	// Add the analyze_starlark tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_starlark",
		Description: "Run the static analyzer on a Starlark code snippet without executing it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params *AnalyzeStarlarkParams) (*mcp.CallToolResult, any, error) {
		err := citron.Analyze(params.Code)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Analysis Failed:\n%v", err)},
				},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Code is safe."},
			},
		}, nil, nil
	})

	// Add the harness guide as a readable resource.
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

	// Create the streamable HTTP handler for SSE
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	log.Printf("Starting Citron MCP server on :%s (HTTP/SSE)", port)
	
	// Ensure that clients can connect
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
