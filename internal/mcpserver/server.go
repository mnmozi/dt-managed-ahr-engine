// Package mcpserver implements a minimal MCP (Model Context Protocol) server
// over stdio for the engine.
//
// MCP is JSON-RPC 2.0 over stdio with a fixed method set. We only implement
// what a tool-server needs:
//
//   - initialize        — handshake
//   - initialized       — client notification, no response
//   - ping              — health check
//   - tools/list        — list available tools
//   - tools/call        — invoke a tool
//
// Anything else returns method_not_found. That's MCP-compliant; the protocol
// allows servers to advertise only the capabilities they implement.
//
// We deliberately avoid pulling in an MCP SDK — the engine has zero
// dependencies (just stdlib) and we want to keep it that way. The protocol
// surface needed is small.
package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/local/dt-managed-engine/internal/elog"
)

// ProtocolVersion is what we advertise on `initialize`. MCP versions are
// dates. We match the version the @modelcontextprotocol/sdk TS client
// negotiates with by default at the time of writing.
const ProtocolVersion = "2024-11-05"

// JSONRPCRequest is a JSON-RPC 2.0 inbound message.
// `ID` is an interface{} because per spec it can be a string, number, or null;
// we echo whatever we receive.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is the success-or-error response shape.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError is the error sub-object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// ToolDef describes one tool the server exposes.
type ToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolHandler runs a tool call. Returns the result content + isError flag.
// On error inside the handler, return (nil, err) and the protocol layer
// will translate that to a JSON-RPC error response.
type ToolHandler func(args json.RawMessage) (CallResult, error)

// CallResult is the MCP tool result shape.
type CallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is one piece of a tool response. We only emit text blocks.
type ContentBlock struct {
	Type string `json:"type"` // always "text" for us
	Text string `json:"text"`
}

// Server is the stdio MCP server. Tools are registered via RegisterTool
// before calling Run.
type Server struct {
	name    string
	version string
	mu      sync.RWMutex
	tools   map[string]registeredTool
}

type registeredTool struct {
	Def     ToolDef
	Handler ToolHandler
}

// New constructs a server with the given name/version metadata.
func New(name, version string) *Server {
	return &Server{
		name:    name,
		version: version,
		tools:   map[string]registeredTool{},
	}
}

// RegisterTool adds a tool. Safe to call before Run; not after.
func (s *Server) RegisterTool(def ToolDef, h ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[def.Name] = registeredTool{Def: def, Handler: h}
}

// Run reads JSON-RPC messages from stdin, writes responses to stdout, and
// logs diagnostics to the structured logger (stderr via slog). Blocks until
// stdin closes or a fatal error occurs.
func (s *Server) Run() error {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	log := elog.Source("mcpserver")

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if perr := s.handleLine(line, writer); perr != nil {
				log.Error("write response failed", "error", perr.Error())
				return perr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}
	}
}

// handleLine parses one inbound JSON-RPC message and writes the response.
// Notifications (no id) are processed silently.
func (s *Server) handleLine(line []byte, w *bufio.Writer) error {
	// MCP allows server-pushed messages too but we don't generate any —
	// every line from the client is a request or notification.
	var req JSONRPCRequest
	if err := json.Unmarshal(line, &req); err != nil {
		// Couldn't parse — emit a parse error with null id.
		return s.writeResponse(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error: &JSONRPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("parse error: %v", err),
			},
		})
	}
	if req.JSONRPC != "2.0" {
		return s.writeResponse(w, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: "jsonrpc must be \"2.0\"",
			},
		})
	}

	// Dispatch by method.
	switch req.Method {
	case "initialize":
		return s.respond(w, req.ID, s.handleInitialize(req.Params), nil)
	case "initialized", "notifications/initialized":
		// Client → server notification, no response expected.
		return nil
	case "ping":
		return s.respond(w, req.ID, map[string]interface{}{}, nil)
	case "tools/list":
		return s.respond(w, req.ID, s.handleToolsList(), nil)
	case "tools/call":
		return s.handleToolsCall(w, req)
	default:
		if req.ID == nil {
			// Notification we don't recognize — silently drop.
			return nil
		}
		return s.respond(w, req.ID, nil, &JSONRPCError{
			Code:    CodeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		})
	}
}

// handleInitialize returns the standard server-capabilities response.
func (s *Server) handleInitialize(_ json.RawMessage) map[string]interface{} {
	return map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    s.name,
			"version": s.version,
		},
	}
}

// handleToolsList returns the registered tools, sorted alphabetically by
// name so the output is stable.
func (s *Server) handleToolsList() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tools := make([]ToolDef, 0, len(s.tools))
	for _, t := range s.tools {
		tools = append(tools, t.Def)
	}
	// alpha sort
	for i := 0; i < len(tools); i++ {
		for j := i + 1; j < len(tools); j++ {
			if tools[i].Name > tools[j].Name {
				tools[i], tools[j] = tools[j], tools[i]
			}
		}
	}
	return map[string]interface{}{"tools": tools}
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// handleToolsCall dispatches to the registered handler.
// Two error shapes are possible:
//   - JSON-RPC error (tool name unknown, params malformed): structured error
//   - Tool reports error: returned as result with isError=true (per MCP spec)
func (s *Server) handleToolsCall(w *bufio.Writer, req JSONRPCRequest) error {
	var p toolsCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return s.respond(w, req.ID, nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: fmt.Sprintf("tools/call params: %v", err),
		})
	}
	s.mu.RLock()
	tool, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return s.respond(w, req.ID, nil, &JSONRPCError{
			Code:    CodeMethodNotFound,
			Message: fmt.Sprintf("unknown tool: %s", p.Name),
		})
	}

	result, err := tool.Handler(p.Arguments)
	if err != nil {
		// Surface as a content block with isError=true. This is MCP-compliant
		// and avoids killing the connection on routine tool failures.
		return s.respond(w, req.ID, CallResult{
			Content: []ContentBlock{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil)
	}
	return s.respond(w, req.ID, result, nil)
}

func (s *Server) respond(w *bufio.Writer, id interface{}, result interface{}, errObj *JSONRPCError) error {
	resp := JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result, Error: errObj}
	return s.writeResponse(w, resp)
}

func (s *Server) writeResponse(w *bufio.Writer, resp JSONRPCResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return err
	}
	return w.Flush()
}
