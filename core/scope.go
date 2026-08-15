package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Scope mirrors the existing Python scope file. Both runtimes therefore use
// one source of truth instead of maintaining separate allowlists.
type Scope struct {
	Program      string   `json:"program"`
	Platform     string   `json:"platform"`
	Authorized   bool     `json:"authorized"`
	RateLimitRPS float64  `json:"rate_limit_rps"`
	InScope      []string `json:"in_scope"`
	OutOfScope   []string `json:"out_of_scope"`
	Rules        string   `json:"rules"`
}

func LoadScope(path string) (Scope, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Scope{}, err
	}
	var scope Scope
	if err := json.Unmarshal(data, &scope); err != nil {
		return Scope{}, fmt.Errorf("decode scope: %w", err)
	}
	if scope.RateLimitRPS <= 0 {
		scope.RateLimitRPS = 2
	}
	return scope, nil
}

func hostOf(target string) string {
	target = strings.TrimSpace(strings.ToLower(target))
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		return strings.TrimSuffix(parsed.Hostname(), ".")
	}
	host := strings.Split(target, "/")[0]
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.Trim(strings.TrimSuffix(host, "."), "[]")
}

func matches(host, pattern string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if parsed, err := url.Parse(pattern); err == nil && parsed.Hostname() != "" {
		pattern = parsed.Hostname()
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}

func (s Scope) Allows(target string) bool {
	host := hostOf(target)
	if host == "" {
		return false
	}
	for _, pattern := range s.OutOfScope {
		if matches(host, pattern) {
			return false
		}
	}
	for _, pattern := range s.InScope {
		if matches(host, pattern) {
			return true
		}
	}
	return false
}

func (s Scope) AssertReady(operatorAuthorized bool) error {
	if len(s.InScope) == 0 {
		return fmt.Errorf("scope is empty")
	}
	if !s.Authorized || !operatorAuthorized {
		return fmt.Errorf("explicit authorization is required")
	}
	return nil
}

// DefaultTargets produces only apex hosts from declared scope entries. A
// wildcard is never enumerated; its base domain is probed once.
func (s Scope) DefaultTargets() []string {
	seen := map[string]bool{}
	var targets []string
	for _, entry := range s.InScope {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if strings.Contains(entry, "://") {
			if s.Allows(entry) && !seen[entry] {
				seen[entry] = true
				targets = append(targets, entry)
			}
			continue
		}
		host := strings.TrimPrefix(entry, "*.")
		// Package IDs are ambiguous in legacy scope files. Explicit --target is
		// preferred; invalid/unresolvable entries simply become error events.
		if host != "" && !strings.ContainsAny(host, " /{}") {
			target := "https://" + host
			if s.Allows(target) && !seen[target] {
				seen[target] = true
				targets = append(targets, target)
			}
		}
	}
	return targets
}
