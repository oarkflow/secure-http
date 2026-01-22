package security

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ConsoleAuditLogger writes human readable audit lines to stdout/stderr.
type ConsoleAuditLogger struct {
	logf func(format string, args ...any)
}

// NewConsoleAuditLogger builds a console logger using log.Printf.
func NewConsoleAuditLogger() ConsoleAuditLogger {
	return ConsoleAuditLogger{logf: log.Printf}
}

// Record implements AuditLogger.
func (l ConsoleAuditLogger) Record(evt AuditEvent) {
	if l.logf == nil {
		return
	}
	if evt.Err != nil {
		l.logf("[AUDIT][%s] capability=%s remote=%s detail=%s err=%v", evt.Type, evt.Capability, evt.RemoteAddr, evt.Detail, evt.Err)
		return
	}
	l.logf("[AUDIT][%s] capability=%s remote=%s detail=%s", evt.Type, evt.Capability, evt.RemoteAddr, evt.Detail)
}

// AsyncFileAuditLogger persists audit events without blocking handlers.
type AsyncFileAuditLogger struct {
	ch       chan AuditEvent
	once     sync.Once
	finished chan struct{}
}

// NewAsyncFileAuditLogger opens (and creates if missing) the provided path.
func NewAsyncFileAuditLogger(path string) (*AsyncFileAuditLogger, error) {
	if path == "" {
		return nil, fmt.Errorf("log path cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	logger := &AsyncFileAuditLogger{
		ch:       make(chan AuditEvent, 256),
		finished: make(chan struct{}),
	}
	go logger.writer(file)
	return logger, nil
}

func (l *AsyncFileAuditLogger) writer(file *os.File) {
	defer close(l.finished)
	defer file.Close()
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for evt := range l.ch {
		payload := map[string]any{
			"type":        evt.Type,
			"session_id":  evt.SessionID,
			"device_id":   evt.DeviceID,
			"user_id":     evt.UserID,
			"capability":  evt.Capability,
			"remote_addr": evt.RemoteAddr,
			"nonce":       evt.Nonce,
			"detail":      evt.Detail,
			"error":       errorString(evt.Err),
			"timestamp":   evt.Timestamp.Format(time.RFC3339Nano),
		}
		if err := encoder.Encode(payload); err != nil {
			log.Printf("async audit write failed: %v", err)
			continue
		}
		writer.Flush()
	}
	writer.Flush()
}

// Record implements AuditLogger.
func (l *AsyncFileAuditLogger) Record(evt AuditEvent) {
	if l == nil {
		return
	}
	select {
	case l.ch <- evt:
	default:
		log.Printf("async audit logger buffer full; dropping event type=%s", evt.Type)
	}
}

// Close flushes remaining events and closes file handles.
func (l *AsyncFileAuditLogger) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.ch)
		<-l.finished
	})
}

// WebhookAuditLogger posts selected events to an external endpoint.
type WebhookAuditLogger struct {
	client      *http.Client
	url         string
	include     map[AuditEventType]struct{}
	minInterval time.Duration
	mu          sync.Mutex
	lastSent    time.Time
}

// NewWebhookAuditLogger constructs the logger.
func NewWebhookAuditLogger(url string, include []AuditEventType, minInterval time.Duration) *WebhookAuditLogger {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	if minInterval <= 0 {
		minInterval = 2 * time.Second
	}
	set := make(map[AuditEventType]struct{}, len(include))
	for _, typ := range include {
		set[typ] = struct{}{}
	}
	if len(set) == 0 {
		set[AuditEventGateDenied] = struct{}{}
		set[AuditEventDecryptFailure] = struct{}{}
		set[AuditEventHandshakeFailure] = struct{}{}
	}
	return &WebhookAuditLogger{
		client:      &http.Client{Timeout: 5 * time.Second},
		url:         url,
		include:     set,
		minInterval: minInterval,
	}
}

// Record implements AuditLogger.
func (l *WebhookAuditLogger) Record(evt AuditEvent) {
	if l == nil {
		return
	}
	if _, ok := l.include[evt.Type]; !ok {
		return
	}
	l.mu.Lock()
	if l.minInterval > 0 && time.Since(l.lastSent) < l.minInterval {
		l.mu.Unlock()
		return
	}
	l.lastSent = time.Now()
	l.mu.Unlock()
	go l.dispatch(evt)
}

func (l *WebhookAuditLogger) dispatch(evt AuditEvent) {
	payload := map[string]any{
		"type":       evt.Type,
		"capability": evt.Capability,
		"detail":     evt.Detail,
		"error":      errorString(evt.Err),
		"timestamp":  evt.Timestamp.Format(time.RFC3339Nano),
	}
	body := bytes.Buffer{}
	if err := json.NewEncoder(&body).Encode(payload); err != nil {
		log.Printf("webhook encode failed: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, l.url, &body)
	if err != nil {
		log.Printf("webhook request build failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		log.Printf("webhook dispatch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		log.Printf("webhook responded with status %d", resp.StatusCode)
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
