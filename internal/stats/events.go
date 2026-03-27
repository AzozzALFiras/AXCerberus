package stats

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// EventType represents a real-time event category.
type EventType string

const (
	EventBlock          EventType = "block"
	EventAttack         EventType = "attack"
	EventDDoSLevel      EventType = "ddos_level_change"
	EventHoneypotHit    EventType = "honeypot_hit"
	EventCredentialBlock EventType = "credential_block"
	EventDLPDetection   EventType = "dlp_detection"
	EventThreatFeed     EventType = "threat_feed_block"
)

// Event is a real-time event emitted to SSE subscribers.
type Event struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// EventBus manages SSE subscribers and event broadcasting.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
}

// NewEventBus creates a new event bus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan Event]struct{}),
	}
}

// Subscribe creates a new subscriber channel.
func (b *EventBus) Subscribe() chan Event {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber.
func (b *EventBus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subscribers, ch)
	b.mu.Unlock()
	close(ch)
}

// Publish sends an event to all subscribers (non-blocking).
func (b *EventBus) Publish(evt Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- evt:
		default:
			// subscriber too slow — drop event
		}
	}
}

// Emit is a convenience method to publish an event with auto-timestamp.
func (b *EventBus) Emit(typ EventType, data any) {
	b.Publish(Event{
		Type:      typ,
		Timestamp: time.Now(),
		Data:      data,
	})
}

// SubscriberCount returns the number of active SSE subscribers.
func (b *EventBus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// HandleSSE is an HTTP handler that streams events via Server-Sent Events.
func (b *EventBus) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			flusher.Flush()
		}
	}
}
