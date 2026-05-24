// Package mcpclient connects to remote MCP servers and transforms their tool
// definitions into citron capabilities. It provides:
//
//   - Connection to remote MCP servers over stdio, SSE, or streamable HTTP
//   - Tool listing (retrieving tool definitions with JSON schemas)
//   - Code generation that produces Starlark bindings for each tool
//
// The generated Go code creates starlark.StringDict entries — each entry is a
// starlark.Builtin that forwards calls to the remote MCP tool.  These builtins
// integrate directly into the citron harness alongside fs, net, proc, and io.
//
// Usage (library):
//
//	import "github.com/mishudark/citron/mcpclient"
//
//	session, err := mcpclient.Connect(ctx, &mcpclient.Config{
//	    Transport: mcpclient.TransportStreamableHTTP,
//	    ServerURL: "http://localhost:8080/mcp",
//	})
//	tools, err := mcpclient.ListTools(ctx, session)
//	code, err := mcpclient.GenerateTools(tools, mcpclient.GenOptions{
//	    PackageName: "mytools",
//	})
//
// The generated code can be written to a .go file and compiled into the
// harness.  At runtime call the registration function to obtain a
// starlark.StringDict that can be merged into the execution context.
package mcpclient

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TransportType selects the wire protocol for connecting to a remote MCP server.
type TransportType int

const (
	// TransportStdio spawns a subprocess and communicates over its stdin/stdout.
	TransportStdio TransportType = iota
	// TransportSSE uses the 2024-11-05 SSE transport (hanging GET + POST).
	TransportSSE
	// TransportStreamableHTTP uses the 2025-03-26+ streamable HTTP transport with
	// session management, standalone SSE, and automatic reconnection.
	TransportStreamableHTTP
)

var transportNames = map[TransportType]string{
	TransportStdio:          "stdio",
	TransportSSE:            "sse",
	TransportStreamableHTTP: "streamable-http",
}

// Config configures a connection to a remote MCP server.
type Config struct {
	// Transport selects the wire protocol.
	Transport TransportType

	// ServerURL is the remote MCP server URL (required for SSE/StreamableHTTP).
	ServerURL string

	// Command is the executable and arguments (required for Stdio).
	Command []string

	// HTTPClient is an optional custom HTTP client (SSE and StreamableHTTP).
	HTTPClient *http.Client

	// ClientInfo is the name and version sent during MCP initialization.
	// Defaults to "citron-mcp-client" / "1.0.0".
	ClientName    string
	ClientVersion string

	// Timeout applied to the initial connection handshake.
	Timeout time.Duration
}

func (c *Config) clientName() string {
	if c.ClientName != "" {
		return c.ClientName
	}
	return "citron-mcp-client"
}

func (c *Config) clientVersion() string {
	if c.ClientVersion != "" {
		return c.ClientVersion
	}
	return "1.0.0"
}

// ToolInfo holds a single MCP tool definition as returned by the remote server.
// InputSchema and OutputSchema are raw JSON Schema objects (properties,
// required, etc.). Both may be nil if the server omits them.
type ToolInfo struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema,omitempty"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
}

// Connect establishes an MCP session with a remote server.
// The caller must call session.Close() when done.
func Connect(ctx context.Context, cfg *Config) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    cfg.clientName(),
		Version: cfg.clientVersion(),
	}, nil)

	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: connect (%s): %w", transportNames[cfg.Transport], err)
	}
	return session, nil
}

// ListTools retrieves all tool definitions from a connected MCP session.
// It handles pagination transparently.
func ListTools(ctx context.Context, session *mcp.ClientSession) ([]*ToolInfo, error) {
	var all []*ToolInfo
	var cursor string

	for {
		result, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("mcpclient: list tools: %w", err)
		}

		for _, t := range result.Tools {
			info := &ToolInfo{
				Name:         t.Name,
				Description:  t.Description,
				InputSchema:  toSchemaMap(t.InputSchema),
				OutputSchema: toSchemaMap(t.OutputSchema),
			}
			all = append(all, info)
		}

		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}

	if all == nil {
		return []*ToolInfo{}, nil
	}
	return all, nil
}

// -- helpers -- //

func newTransport(cfg *Config) (mcp.Transport, error) {
	switch cfg.Transport {
	case TransportStdio:
		if len(cfg.Command) == 0 {
			return nil, fmt.Errorf("mcpclient: Config.Command is required for Stdio transport")
		}
		cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...) //nolint:gosec
		return &mcp.CommandTransport{Command: cmd}, nil

	case TransportSSE:
		if cfg.ServerURL == "" {
			return nil, fmt.Errorf("mcpclient: Config.ServerURL is required for SSE transport")
		}
		return &mcp.SSEClientTransport{
			Endpoint:   cfg.ServerURL,
			HTTPClient: cfg.HTTPClient,
		}, nil

	case TransportStreamableHTTP:
		if cfg.ServerURL == "" {
			return nil, fmt.Errorf("mcpclient: Config.ServerURL is required for StreamableHTTP transport")
		}
		return &mcp.StreamableClientTransport{
			Endpoint:   cfg.ServerURL,
			HTTPClient: cfg.HTTPClient,
		}, nil

	default:
		return nil, fmt.Errorf("mcpclient: unknown transport type %d", cfg.Transport)
	}
}

func toSchemaMap(v any) map[string]any {
	switch val := v.(type) {
	case map[string]any:
		return val
	case nil:
		return nil
	default:
		return nil
	}
}
