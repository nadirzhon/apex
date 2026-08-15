package core

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes = 512_000

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type Config struct {
	Workers    int
	Timeout    time.Duration
	MaxBytes   int64
	UserAgent  string
	Authorized bool
}

type Event struct {
	Type       string         `json:"type"`
	Target     string         `json:"target,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	Value      string         `json:"value,omitempty"`
	Source     string         `json:"source,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
	Error      string         `json:"error,omitempty"`
	Total      int            `json:"total,omitempty"`
	Successful int            `json:"successful,omitempty"`
	Failed     int            `json:"failed,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
}

func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

type Runner struct {
	scope   Scope
	config  Config
	client  *http.Client
	mu      sync.Mutex
	lastHit map[string]time.Time
}

func NewRunner(scope Scope, config Config) *Runner {
	if config.Workers < 1 {
		config.Workers = 8
	}
	if config.Workers > 64 {
		config.Workers = 64
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = maxBodyBytes
	}
	if config.UserAgent == "" {
		config.UserAgent = "APEX-Core/2.0 (authorized bug-bounty automation)"
	}
	runner := &Runner{scope: scope, config: config, lastHit: make(map[string]time.Time)}
	runner.client = &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if !scope.Allows(req.URL.String()) {
				return fmt.Errorf("redirect outside scope: %s", req.URL.Hostname())
			}
			return nil
		},
	}
	return runner
}

func (r *Runner) wait(ctx context.Context, target string) error {
	host := hostOf(target)
	interval := time.Duration(float64(time.Second) / r.scope.RateLimitRPS)
	r.mu.Lock()
	wait := time.Until(r.lastHit[host].Add(interval))
	if wait < 0 {
		wait = 0
	}
	r.lastHit[host] = time.Now().Add(wait)
	r.mu.Unlock()
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *Runner) probe(ctx context.Context, target string) Event {
	started := time.Now()
	if !r.scope.Allows(target) {
		return Event{Type: "error", Target: target, Error: "target outside scope"}
	}
	if err := r.wait(ctx, target); err != nil {
		return Event{Type: "error", Target: target, Error: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Event{Type: "error", Target: target, Error: err.Error()}
	}
	req.Header.Set("User-Agent", r.config.UserAgent)
	resp, err := r.client.Do(req)
	if err != nil {
		return Event{Type: "error", Target: target, Error: err.Error(), DurationMS: time.Since(started).Milliseconds()}
	}
	defer resp.Body.Close()
	if !r.scope.Allows(resp.Request.URL.String()) {
		return Event{Type: "error", Target: target, Error: "final response outside scope"}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, r.config.MaxBytes+1))
	if readErr != nil {
		return Event{Type: "error", Target: target, Error: readErr.Error()}
	}
	truncated := int64(len(body)) > r.config.MaxBytes
	if truncated {
		body = body[:r.config.MaxBytes]
	}
	title := ""
	if match := titlePattern.FindSubmatch(body); len(match) == 2 {
		title = strings.TrimSpace(html.UnescapeString(string(match[1])))
		if len(title) > 160 {
			title = title[:160]
		}
	}
	return Event{
		Type: "asset", Kind: "url", Value: resp.Request.URL.String(), Source: "go-core",
		Meta: map[string]any{
			"status": resp.StatusCode, "server": resp.Header.Get("Server"),
			"content_type": resp.Header.Get("Content-Type"), "title": title,
			"bytes": len(body), "truncated": truncated,
			"duration_ms": time.Since(started).Milliseconds(),
		},
	}
}

func normalizeTargets(scope Scope, targets []string) []string {
	if len(targets) == 0 {
		targets = scope.DefaultTargets()
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		clean = append(clean, target)
	}
	sort.Strings(clean)
	return clean
}

func (r *Runner) Run(ctx context.Context, targets []string) []Event {
	started := time.Now()
	targets = normalizeTargets(r.scope, targets)
	jobs := make(chan string)
	results := make(chan Event, len(targets))
	workers := r.config.Workers
	if len(targets) < workers {
		workers = len(targets)
	}
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for target := range jobs {
				results <- r.probe(ctx, target)
			}
		}()
	}
	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
		group.Wait()
		close(results)
	}()

	events := make([]Event, 0, len(targets)+1)
	successful, failed := 0, 0
	for event := range results {
		if event.Type == "asset" {
			successful++
		} else {
			failed++
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		left := events[i].Target
		if left == "" {
			left = events[i].Value
		}
		right := events[j].Target
		if right == "" {
			right = events[j].Value
		}
		return left < right
	})
	events = append(events, Event{
		Type: "summary", Total: len(targets), Successful: successful,
		Failed: failed, DurationMS: time.Since(started).Milliseconds(),
	})
	return events
}
