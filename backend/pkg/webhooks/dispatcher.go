package webhooks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ============================================================================
// Webhook Event System
//
// Delivers real-time notifications to external systems when events occur.
// Each webhook subscription specifies which events it cares about;
// payloads are HMAC-signed so receivers can verify authenticity.
//
// Events:
//   - flow_completed    — a pentest flow finished successfully
//   - flow_failed       — a flow failed or was stopped
//   - vulnerability_found — a vulnerability was discovered during testing
//   - report_ready      — a report has been generated
//   - task_completed    — a task within a flow completed
//   - attack_pattern_learned — new attack pattern stored in global knowledge
// ============================================================================

// EventType identifies the kind of webhook event.
type EventType string

const (
	EventFlowCompleted        EventType = "flow_completed"
	EventFlowFailed           EventType = "flow_failed"
	EventVulnerabilityFound   EventType = "vulnerability_found"
	EventReportReady          EventType = "report_ready"
	EventTaskCompleted        EventType = "task_completed"
	EventAttackPatternLearned EventType = "attack_pattern_learned"
)

// WebhookPayload is the JSON structure sent to webhook endpoints.
type WebhookPayload struct {
	ID        string    `json:"id"`         // Unique delivery ID
	Event     EventType `json:"event"`      // Event type
	Timestamp time.Time `json:"timestamp"`  // When the event occurred
	Data      any       `json:"data"`       // Event-specific data
}

// FlowCompletedData is sent with EventFlowCompleted.
type FlowCompletedData struct {
	FlowID       int64    `json:"flow_id"`
	FlowTitle    string   `json:"flow_title"`
	TaskCount    int      `json:"task_count"`
	SubtaskCount int      `json:"subtask_count"`
	Duration     float64  `json:"duration_seconds"`
	Techniques   []string `json:"attack_techniques,omitempty"` // MITRE ATT&CK techniques used
}

// VulnerabilityFoundData is sent with EventVulnerabilityFound.
type VulnerabilityFoundData struct {
	FlowID      int64   `json:"flow_id"`
	TaskID      *int64  `json:"task_id,omitempty"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`  // critical, high, medium, low, info
	CVE         string  `json:"cve,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	TechniqueID string  `json:"technique_id,omitempty"` // MITRE ATT&CK
}

// Subscription represents a registered webhook endpoint.
type Subscription struct {
	ID           int64     `json:"id"`
	UserID       int64     `json:"user_id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Secret       string    `json:"-"` // Never expose in API responses
	Events       []string  `json:"events"`
	Enabled      bool      `json:"enabled"`
	FailureCount int       `json:"failure_count"`
	MaxFailures  int       `json:"max_failures"`
	CreatedAt    time.Time `json:"created_at"`
}

// Dispatcher manages webhook delivery with retry and circuit breaking.
type Dispatcher struct {
	subscriptions []Subscription
	client        *http.Client
	mu            sync.RWMutex
	logger        *logrus.Entry

	// Delivery queue — async fire-and-forget to not block the main flow
	deliveryQueue chan deliveryJob
	done          chan struct{}
}

type deliveryJob struct {
	sub     Subscription
	payload WebhookPayload
}

const (
	maxDeliveryQueue  = 1000
	deliveryTimeout   = 10 * time.Second
	maxRetries        = 3
	retryBackoff      = 2 * time.Second
)

// NewDispatcher creates a webhook dispatcher with async delivery.
func NewDispatcher() *Dispatcher {
	d := &Dispatcher{
		subscriptions: make([]Subscription, 0),
		client: &http.Client{
			Timeout: deliveryTimeout,
		},
		logger:        logrus.WithField("component", "webhook-dispatcher"),
		deliveryQueue: make(chan deliveryJob, maxDeliveryQueue),
		done:          make(chan struct{}),
	}

	// Start delivery workers
	for i := 0; i < 3; i++ {
		go d.deliveryWorker(i)
	}

	return d
}

// SetSubscriptions updates the list of active webhook subscriptions.
// Called on startup and when subscriptions are modified via the API.
func (d *Dispatcher) SetSubscriptions(subs []Subscription) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscriptions = subs
}

// Dispatch sends an event to all matching webhook subscriptions.
// Non-blocking — queues delivery for async processing.
func (d *Dispatcher) Dispatch(event EventType, data any) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	payload := WebhookPayload{
		ID:        generateDeliveryID(),
		Event:     event,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	for _, sub := range d.subscriptions {
		if !sub.Enabled {
			continue
		}

		// Check if this subscription cares about this event
		if !containsEvent(sub.Events, string(event)) {
			continue
		}

		// Queue for async delivery
		select {
		case d.deliveryQueue <- deliveryJob{sub: sub, payload: payload}:
		default:
			d.logger.WithFields(logrus.Fields{
				"webhook_id": sub.ID,
				"event":      event,
			}).Warn("webhook delivery queue full, dropping event")
		}
	}
}

// Shutdown stops the delivery workers gracefully.
func (d *Dispatcher) Shutdown() {
	close(d.done)
}

// deliveryWorker processes queued webhook deliveries.
func (d *Dispatcher) deliveryWorker(workerID int) {
	for {
		select {
		case <-d.done:
			return
		case job := <-d.deliveryQueue:
			d.deliver(job)
		}
	}
}

// deliver sends a webhook payload to the subscription URL with HMAC signature.
func (d *Dispatcher) deliver(job deliveryJob) {
	body, err := json.Marshal(job.payload)
	if err != nil {
		d.logger.WithError(err).Error("failed to marshal webhook payload")
		return
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryBackoff * time.Duration(attempt))
		}

		req, err := http.NewRequest(http.MethodPost, job.sub.URL, bytes.NewReader(body))
		if err != nil {
			d.logger.WithError(err).WithField("url", job.sub.URL).Error("failed to create webhook request")
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "PentAGI-Webhook/1.0")
		req.Header.Set("X-PentAGI-Event", string(job.payload.Event))
		req.Header.Set("X-PentAGI-Delivery", job.payload.ID)

		// HMAC signature for payload verification
		if job.sub.Secret != "" {
			signature := computeHMAC(body, job.sub.Secret)
			req.Header.Set("X-PentAGI-Signature", "sha256="+signature)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			d.logger.WithError(err).WithFields(logrus.Fields{
				"webhook_id": job.sub.ID,
				"attempt":    attempt + 1,
			}).Warn("webhook delivery failed")
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			d.logger.WithFields(logrus.Fields{
				"webhook_id": job.sub.ID,
				"event":      job.payload.Event,
				"status":     resp.StatusCode,
			}).Debug("webhook delivered successfully")
			return
		}

		d.logger.WithFields(logrus.Fields{
			"webhook_id": job.sub.ID,
			"status":     resp.StatusCode,
			"attempt":    attempt + 1,
		}).Warn("webhook delivery got non-2xx response")
	}

	d.logger.WithFields(logrus.Fields{
		"webhook_id": job.sub.ID,
		"event":      job.payload.Event,
	}).Error("webhook delivery exhausted all retries")
}

// computeHMAC generates an HMAC-SHA256 signature for payload verification.
func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func containsEvent(events []string, event string) bool {
	for _, e := range events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

func generateDeliveryID() string {
	return fmt.Sprintf("whd_%d", time.Now().UnixNano())
}
