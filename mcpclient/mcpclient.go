// Package mcpclient connects to remote MCP servers and transforms their tool,
// resource, and prompt definitions into citron capabilities. It provides:
//
//   - Connection to remote MCP servers over stdio, SSE, or streamable HTTP
//   - Tool, resource, and prompt listing
//   - Code generation that produces Starlark bindings for tools, resources,
//     and prompts
//
// The generated Go code creates starlark.StringDict entries — each entry is a
// starlark.Builtin that forwards calls to the remote MCP server.  These
// builtins integrate directly into the citron harness alongside fs, net, proc,
// and io.
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
//	code, err := mcpclient.GenerateAll(tools, nil, nil, mcpclient.GenOptions{
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
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxListPages bounds pagination: a malicious or buggy server that never
// stops returning a NextCursor must not loop forever.
const maxListPages = 1000

// paginate advances a paged listing with loop protection.
func paginate(cursor string, seen map[string]bool) (string, error) {
	if cursor == "" {
		return "", nil
	}
	if seen[cursor] {
		return "", fmt.Errorf("mcpclient: server returned a repeated pagination cursor %q", cursor)
	}
	seen[cursor] = true
	if len(seen) > maxListPages {
		return "", fmt.Errorf("mcpclient: pagination did not terminate after %d pages", maxListPages)
	}
	return cursor, nil
}

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

// ResourceInfo holds a single MCP resource definition as returned by the remote server.
type ResourceInfo struct {
	// Name is the logical name of the resource.
	Name string

	// Description is a human-readable description of what this resource represents.
	Description string

	// URI is the resource URI.
	URI string

	// MIMEType is the MIME type of this resource, if known.
	MIMEType string
}

// PromptInfo holds a single MCP prompt definition.
type PromptInfo struct {
	// Name is the logical name of the prompt.
	Name string

	// Description is a human-readable description of what this prompt provides.
	Description string

	// Arguments describes the arguments this prompt accepts.
	Arguments []PromptArgInfo
}

// PromptArgInfo describes a single argument accepted by a prompt.
type PromptArgInfo struct {
	// Name is the argument name.
	Name string

	// Description is a human-readable description of the argument.
	Description string

	// Required indicates whether this argument must be provided.
	Required bool
}

// CapabilityInfo describes a single capability for use in the citron MCP
// server's list_capabilities tool.  It is returned by the server registration
// code generated by GenerateServerTools.
type CapabilityInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Globals     string `json:"globals"`
	Methods     string `json:"methods"`
	Example     string `json:"example"`
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

	// The timeout applies to the handshake only. The session must not be
	// bound to a context we cancel when Connect returns: cancelling would
	// tear down the connection immediately. The session context therefore
	// outlives this call; its lifetime ends with session.Close().
	sessionCtx := context.WithoutCancel(ctx)
	type connectResult struct {
		session *mcp.ClientSession
		err     error
	}
	ch := make(chan connectResult, 1)
	go func() {
		s, e := client.Connect(sessionCtx, transport, nil)
		ch <- connectResult{s, e}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("mcpclient: connect (%s): %w", transportNames[cfg.Transport], r.err)
		}
		return r.session, nil
	case <-timer.C:
		if closer, ok := transport.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, fmt.Errorf("mcpclient: connect (%s): timed out after %v", transportNames[cfg.Transport], timeout)
	}
}

// ListTools retrieves all tool definitions from a connected MCP session.
// It handles pagination transparently.
func ListTools(ctx context.Context, session *mcp.ClientSession) ([]*ToolInfo, error) {
	var all []*ToolInfo
	var cursor string
	seen := make(map[string]bool)

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
		next, err := paginate(result.NextCursor, seen)
		if err != nil {
			return nil, err
		}
		cursor = next
	}

	if all == nil {
		return []*ToolInfo{}, nil
	}
	return all, nil
}

// ListResources retrieves all resource definitions from a connected MCP session.
// It handles pagination transparently.
func ListResources(ctx context.Context, session *mcp.ClientSession) ([]*ResourceInfo, error) {
	var all []*ResourceInfo
	var cursor string
	seen := make(map[string]bool)
	for {
		result, err := session.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("mcpclient: list resources: %w", err)
		}
		for _, r := range result.Resources {
			all = append(all, &ResourceInfo{
				Name:        r.Name,
				Description: r.Description,
				URI:         r.URI,
				MIMEType:    r.MIMEType,
			})
		}
		if result.NextCursor == "" {
			break
		}
		next, err := paginate(result.NextCursor, seen)
		if err != nil {
			return nil, err
		}
		cursor = next
	}
	if all == nil {
		return []*ResourceInfo{}, nil
	}
	return all, nil
}

// ListPrompts retrieves all prompt definitions from a connected MCP session.
// It handles pagination transparently.
func ListPrompts(ctx context.Context, session *mcp.ClientSession) ([]*PromptInfo, error) {
	var all []*PromptInfo
	var cursor string
	seen := make(map[string]bool)
	for {
		result, err := session.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("mcpclient: list prompts: %w", err)
		}
		for _, p := range result.Prompts {
			info := &PromptInfo{
				Name:        p.Name,
				Description: p.Description,
			}
			for _, a := range p.Arguments {
				info.Arguments = append(info.Arguments, PromptArgInfo{
					Name:        a.Name,
					Description: a.Description,
					Required:    a.Required,
				})
			}
			all = append(all, info)
		}
		if result.NextCursor == "" {
			break
		}
		next, err := paginate(result.NextCursor, seen)
		if err != nil {
			return nil, err
		}
		cursor = next
	}
	if all == nil {
		return []*PromptInfo{}, nil
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
