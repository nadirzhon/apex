package core

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestRunnerProbesLocalScopedTarget(t *testing.T) {
	scope := Scope{Authorized: true, RateLimitRPS: 100, InScope: []string{"lab.example"}}
	runner := NewRunner(scope, Config{Workers: 4, Timeout: time.Second, Authorized: true})
	runner.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Server":       []string{"apex-test"},
				"Content-Type": []string{"text/html"},
			},
			Body:    io.NopCloser(strings.NewReader("<html><title>Local Lab</title></html>")),
			Request: request,
		}, nil
	})

	events := runner.Run(context.Background(), []string{"https://lab.example"})
	if len(events) != 2 || events[0].Type != "asset" || events[1].Type != "summary" {
		t.Fatalf("unexpected events: %#v", events)
	}
	if events[0].Meta["title"] != "Local Lab" {
		t.Fatalf("title not extracted: %#v", events[0].Meta)
	}
}

func TestRunnerRejectsOutsideScopeBeforeRequest(t *testing.T) {
	scope := Scope{Authorized: true, RateLimitRPS: 100, InScope: []string{"example.com"}}
	runner := NewRunner(scope, Config{Workers: 1, Timeout: time.Second, Authorized: true})
	events := runner.Run(context.Background(), []string{"http://127.0.0.1:1"})
	if events[0].Type != "error" || events[0].Error != "target outside scope" {
		t.Fatalf("unexpected event: %#v", events[0])
	}
}
