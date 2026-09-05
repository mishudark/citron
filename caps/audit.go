package caps

import (
	"sync"
	"time"
)

// AuditEvent records a classified-data operation without ever carrying the
// classified content itself: Detail holds a path, URL, or command name only.
type AuditEvent struct {
	Time   time.Time `json:"time"`
	Op     string    `json:"op"`
	Detail string    `json:"detail"`
	Err    string    `json:"error,omitempty"`
}

var (
	auditMu  sync.Mutex
	auditLog []AuditEvent
)

// RecordAudit appends a classified-data audit event. It is always on: audit
// volume is low (one entry per classified operation) and a tamper-evident
// default beats an opt-in one.
func RecordAudit(op, detail string, err error) {
	e := AuditEvent{Time: time.Now(), Op: op, Detail: detail}
	if err != nil {
		e.Err = err.Error()
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLog = append(auditLog, e)
}

// AuditLen returns the current number of audit events, so a caller can
// snapshot the position before an execution.
func AuditLen() int {
	auditMu.Lock()
	defer auditMu.Unlock()
	return len(auditLog)
}

// AuditEvents returns audit events recorded after the given snapshot index.
func AuditEvents(since int) []AuditEvent {
	auditMu.Lock()
	defer auditMu.Unlock()
	if since >= len(auditLog) {
		return nil
	}
	out := make([]AuditEvent, len(auditLog)-since)
	copy(out, auditLog[since:])
	return out
}
