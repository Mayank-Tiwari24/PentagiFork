package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// ============================================================================
// Immutable Audit Logging
//
// Records all security-relevant actions: who did what, when, from where.
// The audit_logs table is protected by a DB trigger that prevents UPDATE/DELETE.
// This module provides:
//   - AuditLogger: writes audit entries to the database
//   - Gin middleware: auto-logs API requests (configurable per-route)
//   - Structured event types for consistent querying
// ============================================================================

// Action defines the type of auditable action.
type Action string

const (
	// Auth events
	ActionUserLogin          Action = "user.login"
	ActionUserLogout         Action = "user.logout"
	ActionUserLoginFailed    Action = "user.login_failed"
	ActionOAuthLogin         Action = "user.oauth_login"

	// User management
	ActionUserCreate         Action = "user.create"
	ActionUserUpdate         Action = "user.update"
	ActionUserDelete         Action = "user.delete"
	ActionPasswordChange     Action = "user.password_change"

	// Flow operations
	ActionFlowCreate         Action = "flow.create"
	ActionFlowDelete         Action = "flow.delete"
	ActionFlowStop           Action = "flow.stop"
	ActionFlowFinish         Action = "flow.finish"
	ActionFlowInput          Action = "flow.input"

	// Provider management
	ActionProviderCreate     Action = "provider.create"
	ActionProviderUpdate     Action = "provider.update"
	ActionProviderDelete     Action = "provider.delete"
	ActionProviderTest       Action = "provider.test"

	// API token management
	ActionTokenCreate        Action = "token.create"
	ActionTokenUpdate        Action = "token.update"
	ActionTokenDelete        Action = "token.delete"
	ActionTokenRevoke        Action = "token.revoke"

	// Settings
	ActionPromptCreate       Action = "prompt.create"
	ActionPromptUpdate       Action = "prompt.update"
	ActionPromptDelete       Action = "prompt.delete"

	// Knowledge
	ActionKnowledgeCreate    Action = "knowledge.create"
	ActionKnowledgeUpdate    Action = "knowledge.update"
	ActionKnowledgeDelete    Action = "knowledge.delete"

	// Webhooks
	ActionWebhookCreate      Action = "webhook.create"
	ActionWebhookUpdate      Action = "webhook.update"
	ActionWebhookDelete      Action = "webhook.delete"

	// Plugin management
	ActionPluginInstall      Action = "plugin.install"
	ActionPluginUninstall    Action = "plugin.uninstall"
	ActionPluginEnable       Action = "plugin.enable"
	ActionPluginDisable      Action = "plugin.disable"
)

// ResourceType identifies the kind of resource being acted upon.
type ResourceType string

const (
	ResourceUser       ResourceType = "user"
	ResourceFlow       ResourceType = "flow"
	ResourceProvider   ResourceType = "provider"
	ResourceToken      ResourceType = "token"
	ResourcePrompt     ResourceType = "prompt"
	ResourceKnowledge  ResourceType = "knowledge"
	ResourceWebhook    ResourceType = "webhook"
	ResourcePlugin     ResourceType = "plugin"
	ResourceAssistant  ResourceType = "assistant"
)

// Entry represents a single audit log record.
type Entry struct {
	UserID       *int64         `json:"user_id,omitempty"`
	Action       Action         `json:"action"`
	ResourceType ResourceType   `json:"resource_type"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
}

// Logger writes audit entries to the database.
type Logger struct {
	db     *sql.DB
	logger *logrus.Entry

	// Async channel for non-blocking writes
	entries chan Entry
	done    chan struct{}
}

// NewLogger creates an audit logger that writes to the audit_logs table.
func NewLogger(db *sql.DB) *Logger {
	l := &Logger{
		db:      db,
		logger:  logrus.WithField("component", "audit-logger"),
		entries: make(chan Entry, 5000),
		done:    make(chan struct{}),
	}

	// Start async writer — audit writes should never block API responses
	go l.writer()

	return l
}

// Log records an audit entry. Non-blocking — queues for async persistence.
func (l *Logger) Log(entry Entry) {
	select {
	case l.entries <- entry:
	default:
		// Queue full — log and drop (never block the API)
		l.logger.WithFields(logrus.Fields{
			"action":        entry.Action,
			"resource_type": entry.ResourceType,
		}).Warn("audit log queue full, entry dropped")
	}
}

// LogFromRequest enriches an audit entry with HTTP request metadata and queues it.
// Use this from Gin handlers or any HTTP middleware.
func (l *Logger) LogFromRequest(r *http.Request, entry Entry) {
	if r != nil {
		entry.IPAddress = r.RemoteAddr
		entry.UserAgent = r.UserAgent()
	}
	l.Log(entry)
}

// LogSync writes an audit entry synchronously — use for critical events
// (login failures, token creation) where guaranteed persistence matters.
func (l *Logger) LogSync(entry Entry) error {
	return l.persist(entry)
}

// Shutdown flushes remaining entries and stops the writer.
func (l *Logger) Shutdown(ctx context.Context) {
	close(l.done)

	// Drain remaining entries
	for {
		select {
		case entry := <-l.entries:
			_ = l.persist(entry)
		case <-ctx.Done():
			return
		default:
			return
		}
	}
}

func (l *Logger) writer() {
	for {
		select {
		case <-l.done:
			return
		case entry := <-l.entries:
			if err := l.persist(entry); err != nil {
				l.logger.WithError(err).WithField("action", entry.Action).Error("failed to persist audit entry")
			}
		}
	}
}

func (l *Logger) persist(entry Entry) error {
	detailsJSON, _ := json.Marshal(entry.Details)

	_, err := l.db.Exec(`
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		entry.UserID,
		string(entry.Action),
		string(entry.ResourceType),
		entry.ResourceID,
		detailsJSON,
		entry.IPAddress,
		entry.UserAgent,
	)
	return err
}

// ============================================================================
// Query helpers for reading audit logs
// ============================================================================

// AuditRecord is the database representation of an audit entry.
type AuditRecord struct {
	ID           int64          `json:"id"`
	UserID       *int64         `json:"user_id,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Details      map[string]any `json:"details,omitempty"`
	IPAddress    string         `json:"ip_address"`
	UserAgent    string         `json:"user_agent"`
	CreatedAt    time.Time      `json:"created_at"`
}

// QueryOptions filters audit log queries.
type QueryOptions struct {
	UserID       *int64
	Action       *Action
	ResourceType *ResourceType
	ResourceID   *string
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}
