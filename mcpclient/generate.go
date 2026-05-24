package mcpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"strings"
	"text/template"
)

// GenOptions configures the Go code generator.
type GenOptions struct {
	// PackageName is the Go package name of the generated file (required).
	PackageName string

	// FuncName is the name of the generated registration function.
	// Default: "RegisterMCPSession".
	FuncName string

	// Tag is an optional build tag placed at the top of the generated file.
	Tag string
}

// GenerateTools produces formatted Go source code that creates Starlark
// builtins for every MCP tool listed in tools.  The generated code is a
// complete .go file ready to write to disk and compile.
//
// The generated file exports a function (FuncName, default RegisterMCPSession)
// with the signature:
//
//	func RegisterMCPSession(session *mcp.ClientSession) starlark.StringDict
//
// Each tool becomes a starlark.Builtin that accepts keyword arguments,
// forwards them to the remote MCP server via session.CallTool, and returns
// the result as a starlark.Value.  Argument names and descriptions from the
// JSON schema properties are included as comments.
//
// Deprecated: Use GenerateAll instead, which supports tools, resources, and
// prompts in a single call.
func GenerateTools(tools []*ToolInfo, opts GenOptions) ([]byte, error) {
	return GenerateAll(tools, nil, nil, opts)
}

// GenerateAll produces formatted Go source code that creates Starlark builtins
// for every MCP tool, resource, and prompt advertised by the remote server.
// The generated code is a complete .go file ready to write to disk and
// compile.
//
// The generated file exports a function (FuncName, default RegisterMCPSession)
// with the signature:
//
//	func RegisterMCPSession(session *mcp.ClientSession) starlark.StringDict
//
// Each tool becomes a starlark.Builtin that accepts keyword arguments,
// forwards them to the remote MCP server via session.CallTool, and returns
// the result as a starlark.Value.
//
// Each resource becomes a starlark.Builtin named get_<resource> that reads
// the resource via session.ReadResource.  Each prompt becomes a
// starlark.Builtin named <prompt> that retrieves the prompt via
// session.GetPrompt.
//
// Any of tools, resources, or prompts may be nil.
func GenerateAll(tools []*ToolInfo, resources []*ResourceInfo, prompts []*PromptInfo, opts GenOptions) ([]byte, error) {
	if opts.PackageName == "" {
		return nil, fmt.Errorf("mcpclient: GenOptions.PackageName is required")
	}
	if opts.FuncName == "" {
		opts.FuncName = "RegisterMCPSession"
	}

	// Build template data.
	data := &genData{
		PackageName:  opts.PackageName,
		FuncName:     opts.FuncName,
		HasTools:     len(tools) > 0,
		Tools:        make([]genTool, len(tools)),
		HasResources: len(resources) > 0,
		Resources:    make([]genResource, len(resources)),
		HasPrompts:   len(prompts) > 0,
		Prompts:      make([]genPrompt, len(prompts)),
	}

	for i, t := range tools {
		gt := genTool{
			Name:            t.Name,
			Description:     t.Description,
			InputPropNames:  extractPropertyNames(t.InputSchema),
			OutputPropNames: extractPropertyNames(t.OutputSchema),
		}

		// Build a user-friendly description comment.
		var sb strings.Builder
		sb.WriteString(escapeComment(t.Name))
		if t.Description != "" {
			sb.WriteString(" - ")
			sb.WriteString(escapeComment(t.Description))
		}

		hasSchema := len(gt.InputPropNames) > 0 || len(gt.OutputPropNames) > 0
		if hasSchema {
			sb.WriteString("\n//")
		}
		if len(gt.InputPropNames) > 0 {
			sb.WriteString("\n// Inputs:")
			for _, p := range gt.InputPropNames {
				sb.WriteString("\n//   ")
				sb.WriteString(escapeComment(p))
			}
		}
		if len(gt.OutputPropNames) > 0 {
			sb.WriteString("\n// Outputs:")
			for _, p := range gt.OutputPropNames {
				sb.WriteString("\n//   ")
				sb.WriteString(escapeComment(p))
			}
		}
		gt.Doc = sb.String()

		data.Tools[i] = gt
	}

	for i, r := range resources {
		gr := genResource{
			Name:        r.Name,
			Description: r.Description,
			URI:         r.URI,
			MIMEType:    r.MIMEType,
			FuncName:    "get_" + r.Name,
		}

		// Build doc comment.
		var sb strings.Builder
		sb.WriteString(escapeComment(r.Name))
		if r.Description != "" {
			sb.WriteString(" - ")
			sb.WriteString(escapeComment(r.Description))
		}
		sb.WriteString("\n// URI: ")
		sb.WriteString(escapeComment(r.URI))
		if r.MIMEType != "" {
			sb.WriteString("\n// MIME: ")
			sb.WriteString(escapeComment(r.MIMEType))
		}
		gr.Doc = sb.String()

		data.Resources[i] = gr
	}

	for i, p := range prompts {
		gp := genPrompt{
			Name:        p.Name,
			Description: p.Description,
			ArgNames:    make([]string, len(p.Arguments)),
		}
		for j, a := range p.Arguments {
			gp.ArgNames[j] = a.Name
		}

		// Build doc comment.
		var sb strings.Builder
		sb.WriteString(escapeComment(p.Name))
		if p.Description != "" {
			sb.WriteString(" - ")
			sb.WriteString(escapeComment(p.Description))
		}
		if len(gp.ArgNames) > 0 {
			sb.WriteString("\n// Arguments:")
			for _, n := range gp.ArgNames {
				sb.WriteString("\n//   ")
				sb.WriteString(escapeComment(n))
			}
		}
		gp.Doc = sb.String()

		data.Prompts[i] = gp
	}

	// Execute the template.
	var buf bytes.Buffer
	if err := genTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("mcpclient: template execute: %w", err)
	}

	// gofmt the output.
	out, err := format.Source(buf.Bytes())
	if err != nil {
		// Return the unformatted source as a fallback so the user can inspect.
		return buf.Bytes(), fmt.Errorf("mcpclient: format source: %w", err)
	}
	return out, nil
}

// -- template data types -- //

type genData struct {
	PackageName  string
	FuncName     string
	HasTools     bool
	Tools        []genTool
	HasResources bool
	Resources    []genResource
	HasPrompts   bool
	Prompts      []genPrompt
	Tag          string
}

type genTool struct {
	Name            string
	Description     string
	Doc             string // full comment block for the entry
	InputPropNames  []string
	OutputPropNames []string
}

type genResource struct {
	Name        string
	Description string
	Doc         string
	URI         string
	MIMEType    string
	// FuncNameG is the Starlark builtin name for reading this resource.
	FuncName    string
}

type genPrompt struct {
	Name        string
	Description string
	Doc         string
	ArgNames    []string
}

// -- helpers -- //

func extractPropertyNames(schema map[string]any) []string {
	if schema == nil {
		return nil
	}
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	return names
}

func escapeComment(s string) string {
	// The template adds "// " prefix; just ensure no unprintable chars.
	return strings.ReplaceAll(s, "\n", " ")
}

// schemaToJSON serializes a JSON Schema map into a Go expression suitable
// for embedding in generated code.  Returns "nil" for nil input, or returns
// a backtick raw string literal containing the JSON.
func schemaToJSON(schema map[string]any) string {
	if schema == nil {
		return "nil"
	}
	data, err := json.Marshal(schema)
	if err != nil {
		return "nil"
	}
	return "`" + string(data) + "`"
}

// buildMethodsString generates a Methods string for CapabilityInfo from a
// tool's input property names and their types.  Format:
//
//	tool_name(param1=<type>, param2=<type>)
func buildMethodsString(name string, propNames []string, schema map[string]any) string {
	if len(propNames) == 0 {
		return name + "()"
	}
	props, _ := schema["properties"].(map[string]any)

	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteString("(")
	for i, p := range propNames {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p)
		sb.WriteString("=<")
		if props != nil {
			if prop, ok := props[p].(map[string]any); ok {
				if t, ok := prop["type"].(string); ok {
					sb.WriteString(t)
				} else {
					sb.WriteString("any")
				}
				if enum, ok := prop["enum"].([]any); ok {
					sb.WriteString("|")
					for j, e := range enum {
						if j > 0 {
							sb.WriteString("|")
						}
						sb.WriteString(fmt.Sprint(e))
					}
				}
			} else {
				sb.WriteString("any")
			}
		} else {
			sb.WriteString("any")
		}
		sb.WriteString(">")
	}
	sb.WriteString(")")
	return sb.String()
}

// buildExampleString generates a short Example string for CapabilityInfo.
func buildExampleString(name string, propNames []string) string {
	if len(propNames) == 0 {
		return name + "()"
	}
	var sb strings.Builder
	sb.WriteString("result = ")
	sb.WriteString(name)
	sb.WriteString("(")
	for i, p := range propNames {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p)
		sb.WriteString(`="<`)
		sb.WriteString(p)
		sb.WriteString(`>"`)
	}
	sb.WriteString(")")
	return sb.String()
}

// -- server registration template -- //

type genServerData struct {
	PackageName string
	Tag         string
	HasTools    bool
	Tools       []genServerTool
}

type genServerTool struct {
	Name           string
	Description    string
	InputSchema    string // JSON-encoded schema
	InputPropNames []string
	MethodsStr     string
	ExampleStr     string
}

// GenerateServerTools produces formatted Go source code that registers every
// MCP tool as a local MCP tool on a citron server.  The generated code
// proxies all calls to the remote session.
//
// The generated file exports a function:
//
//	func RegisterRemoteTools(server *mcp.Server, session *mcp.ClientSession) []mcpclient.CapabilityInfo
//
// The returned CapabilityInfo slice can be merged into the list_capabilities
// tool response in the citron MCP server.
func GenerateServerTools(tools []*ToolInfo, opts GenOptions) ([]byte, error) {
	if opts.PackageName == "" {
		return nil, fmt.Errorf("mcpclient: GenOptions.PackageName is required")
	}
	if opts.FuncName == "" {
		opts.FuncName = "RegisterRemoteTools"
	}

	data := &genServerData{
		PackageName: opts.PackageName,
		HasTools:    len(tools) > 0,
		Tools:       make([]genServerTool, len(tools)),
	}

	for i, t := range tools {
		propNames := extractPropertyNames(t.InputSchema)

		st := genServerTool{
			Name:           t.Name,
			Description:    t.Description,
			InputSchema:    schemaToJSON(t.InputSchema),
			InputPropNames: propNames,
			MethodsStr:     buildMethodsString(t.Name, propNames, t.InputSchema),
			ExampleStr:     buildExampleString(t.Name, propNames),
		}
		data.Tools[i] = st
	}

	var buf bytes.Buffer
	if err := serverTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("mcpclient: server template execute: %w", err)
	}

	out, err := format.Source(buf.Bytes())
	if err != nil {
		return buf.Bytes(), fmt.Errorf("mcpclient: format server source: %w", err)
	}
	return out, nil
}

var serverTemplate = template.Must(template.New("server").Funcs(template.FuncMap{
	"quote": func(s string) string { return fmt.Sprintf("%q", s) },
}).Parse(`// Code generated by mcpclient. DO NOT EDIT.
// Source: github.com/mishudark/citron/mcpclient

{{- if .Tag }}
//go:build {{.Tag}}
{{- end }}

package {{.PackageName}}

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mishudark/citron/mcpclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterRemoteTools registers each remote MCP tool as a local MCP tool on
// the given server. All calls are proxied to the remote session.  It returns
// capability descriptions that can be merged into the list_capabilities tool
// response.
func RegisterRemoteTools(server *mcp.Server, session *mcp.ClientSession) []mcpclient.CapabilityInfo {
	var capabilities []mcpclient.CapabilityInfo
	_ = capabilities
	{{- range .Tools }}
	server.AddTool(&mcp.Tool{
		Name:        {{.Name | quote}},
		Description: {{.Description | quote}},
		InputSchema: json.RawMessage({{.InputSchema}}),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, fmt.Errorf("invalid arguments for %s: %w", {{.Name | quote}}, err)
			}
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      {{.Name | quote}},
			Arguments: args,
		})
		if err != nil {
			return nil, fmt.Errorf("remote tool %s: %w", {{.Name | quote}}, err)
		}
		return result, nil
	})
	capabilities = append(capabilities, mcpclient.CapabilityInfo{
		Name:        {{.Name | quote}},
		Description: {{.Description | quote}},
		Globals:     {{.Name | quote}} + " (remote MCP tool)",
		Methods:     {{.MethodsStr | quote}},
		Example:     {{.ExampleStr | quote}},
	})
	{{- end }}
	return capabilities
}
`))

// -- template -- //

var genTemplate = template.Must(template.New("gen").Funcs(template.FuncMap{
	"quote": func(s string) string { return fmt.Sprintf("%q", s) },
	"trim":  strings.TrimSpace,
}).Parse(`// Code generated by mcpclient. DO NOT EDIT.
// Source: github.com/mishudark/citron/mcpclient

{{- if .Tag }}
//go:build {{.Tag}}
{{- end }}

package {{.PackageName}}

import (
	"context"
	"fmt"

	"github.com/mishudark/citron/mcpclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"
)

// {{.FuncName}} creates Starlark builtins for every MCP tool, resource, and
// prompt advertised by the remote server. The returned starlark.StringDict can
// be merged into a citron execution context so that Starlark code can call the
// remote tools, read resources, and retrieve prompts.
//
// Example:
//
//	dict := RegisterMCPSession(session)
//	starlark.ExecFile(thread, "agent.star", code, dict)
func {{.FuncName}}(session *mcp.ClientSession) starlark.StringDict {
	_ = session // ensure session is "used" even when there are no entries
	{{- if not .HasTools }}{{ if not .HasResources }}{{ if not .HasPrompts }}
	return starlark.StringDict{}
	{{- end }}{{ end }}{{ end }}
	{{- if or .HasTools .HasResources .HasPrompts }}
	return starlark.StringDict{
	{{- end }}
	{{- if .HasTools }}
	{{- range .Tools }}
		// {{.Doc}}
		{{.Name | quote}}: starlark.NewBuiltin({{.Name | quote}}, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			params := make(map[string]any, len(kwargs))
			for _, kv := range kwargs {
				params[string(kv[0].(starlark.String))] = mcpclient.FromStarlark(kv[1])
			}
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      {{.Name | quote}},
				Arguments: params,
			})
			if err != nil {
				return nil, fmt.Errorf("mcp tool %s: %w", {{.Name | quote}}, err)
			}
			return mcpclient.MCPResultToStarlark(result)
		}),
	{{- end }}
	{{- end }}
	{{- if .HasResources }}
	{{- range .Resources }}
		// {{.Doc}}
		{{.FuncName | quote}}: starlark.NewBuiltin({{.FuncName | quote}}, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{
				URI: {{.URI | quote}},
			})
			if err != nil {
				return nil, fmt.Errorf("mcp resource %s: %w", {{.Name | quote}}, err)
			}
			return mcpclient.ReadResourceResultToStarlark(result)
		}),
	{{- end }}
	{{- end }}
	{{- if .HasPrompts }}
	{{- range .Prompts }}
		// {{.Doc}}
		{{.Name | quote}}: starlark.NewBuiltin({{.Name | quote}}, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			argMap := make(map[string]string, len(kwargs))
			for _, kv := range kwargs {
				key := string(kv[0].(starlark.String))
				val, _ := starlark.AsString(kv[1])
				argMap[key] = val
			}
			result, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
				Name:      {{.Name | quote}},
				Arguments: argMap,
			})
			if err != nil {
				return nil, fmt.Errorf("mcp prompt %s: %w", {{.Name | quote}}, err)
			}
			return mcpclient.GetPromptResultToStarlark(result)
		}),
	{{- end }}
	{{- end }}
	{{- if or .HasTools .HasResources .HasPrompts }}
	}
	{{- end }}
}
`))
