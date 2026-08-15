package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nadirzhon/apex/core"
)

type targetsFlag []string

func (t *targetsFlag) String() string { return strings.Join(*t, ",") }
func (t *targetsFlag) Set(value string) error {
	*t = append(*t, value)
	return nil
}

func main() {
	var targets targetsFlag
	scopePath := flag.String("scope", "program.json", "path to APEX scope JSON")
	authorized := flag.Bool("authorized", false, "confirm authorization for this scope")
	workers := flag.Int("workers", 8, "concurrent workers (1-64)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Var(&targets, "target", "explicit in-scope URL (repeatable)")
	flag.Parse()

	scope, err := core.LoadScope(*scopePath)
	if err != nil {
		fatal(err)
	}
	if err := scope.AssertReady(*authorized); err != nil {
		fatal(err)
	}
	runner := core.NewRunner(scope, core.Config{
		Workers: *workers, Timeout: *timeout, Authorized: *authorized,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(os.Stdout)
	for _, event := range runner.Run(ctx, targets) {
		if err := encoder.Encode(event); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "apex-core:", err)
	os.Exit(2)
}
