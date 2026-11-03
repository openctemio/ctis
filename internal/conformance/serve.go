package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MaxRequestBytes bounds one request line of the protocol.
const MaxRequestBytes = 64 << 20

type request struct {
	ID    json.RawMessage `json:"id"`
	Op    string          `json:"op"`
	Input json.RawMessage `json:"input"`
}

type response struct {
	ID     json.RawMessage `json:"id"`
	Output any             `json:"output"`
	Error  *OpError        `json:"error,omitempty"`
}

// errorResponse is a response without an output member.
type errorResponse struct {
	ID    json.RawMessage `json:"id"`
	Error *OpError        `json:"error"`
}

// Serve answers protocol requests (conformance/PROTOCOL.md): one JSON
// object per line on r, one answer per line on w, in order. It returns when
// r ends, or with the error of a failed read or write. implementation and
// version name this implementation in the answer to "info".
func Serve(r io.Reader, w io.Writer, implementation, version string) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxRequestBytes)
	bw := bufio.NewWriter(w)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := writeLine(bw, answer(line, implementation, version)); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		// A line over MaxRequestBytes: answer it, then stop (the stream
		// cannot be resynchronised).
		_ = writeLine(bw, errorResponse{ID: json.RawMessage("null"), Error: &OpError{Category: CategoryProtocol, Message: err.Error()}})
		_ = bw.Flush()
		return err
	}
	return bw.Flush()
}

func answer(line []byte, implementation, version string) any {
	var req request
	if err := strict(line, &req); err != nil {
		return errorResponse{ID: json.RawMessage("null"), Error: &OpError{Category: CategoryProtocol, Message: fmt.Sprintf("request is not a protocol object: %v", err)}}
	}
	id := req.ID
	if id == nil {
		id = json.RawMessage("null")
	}
	if req.Op == "info" {
		return response{ID: id, Output: Info(implementation, version)}
	}
	if req.Input == nil {
		return errorResponse{ID: id, Error: &OpError{Category: CategoryProtocol, Message: "input is required"}}
	}
	out, e := Do(req.Op, req.Input)
	if e != nil {
		return errorResponse{ID: id, Error: e}
	}
	return response{ID: id, Output: out}
}

func writeLine(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Unreachable for the values Do returns; answer rather than stop.
		buf.Reset()
		_ = enc.Encode(errorResponse{ID: json.RawMessage("null"), Error: &OpError{Category: CategoryProtocol, Message: err.Error()}})
	}
	_, err := w.Write(buf.Bytes())
	return err
}
