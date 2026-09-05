package caps

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type secureSink struct {
	w  io.Writer
	mu sync.Mutex
}

type IOCapability struct {
	secure   *secureSink
	agentOut io.Writer
	mu       sync.Mutex
}

func NewIOCapability(secureOut io.Writer, agentOut io.Writer) *IOCapability {
	var sink *secureSink
	if secureOut != nil {
		sink = &secureSink{w: secureOut}
	}
	if agentOut == nil {
		agentOut = os.Stdout
	}
	return &IOCapability{secure: sink, agentOut: agentOut}
}

func (io *IOCapability) Println(a ...any) {
	io.mu.Lock()
	defer io.mu.Unlock()
	_, _ = fmt.Fprintln(io.agentOut, a...)
	io.writeSecure(a...)
	io.writeNewline()
}

func (io *IOCapability) Print(a ...any) {
	io.mu.Lock()
	defer io.mu.Unlock()
	_, _ = fmt.Fprint(io.agentOut, a...)
	io.writeSecure(a...)
}

func (io *IOCapability) Printf(format string, a ...any) {
	io.mu.Lock()
	defer io.mu.Unlock()
	_, _ = fmt.Fprintf(io.agentOut, format, a...)
	io.writeSecure(fmt.Sprintf(format, a...))
}

func (io *IOCapability) writeSecure(a ...any) {
	if io.secure == nil {
		return
	}
	io.secure.mu.Lock()
	defer io.secure.mu.Unlock()
	unmasked := false
	for _, v := range a {
		if u, ok := v.(unmasker); ok {
			unmasked = true
			_, _ = fmt.Fprint(io.secure.w, u.unmask())
		} else {
			_, _ = fmt.Fprint(io.secure.w, v)
		}
	}
	if unmasked {
		RecordAudit("io.unmask", "secure sink", nil)
	}
}

func (io *IOCapability) writeNewline() {
	if io.secure == nil {
		return
	}
	_, _ = io.secure.w.Write([]byte{'\n'})
}
