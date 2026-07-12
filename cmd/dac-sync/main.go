// Entry point: loads local rule files, syncs each one to Kibana, and exits 1 if any rule failed.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dac-sync/internal/kibana"
	"dac-sync/internal/rule"
	"dac-sync/internal/syncer"
)

func main() {
	var (
		kibanaURL = flag.String("kibana", envOr("KIBANA_URL", "http://localhost:5601"),
			"Kibana base URL; may include a space prefix (e.g. http://host:5601/s/secops)")
		user = flag.String("user", os.Getenv("KIBANA_USER"),
			"basic auth user (or env KIBANA_USER)")
		pass = flag.String("pass", os.Getenv("KIBANA_PASS"),
			"basic auth password (or env KIBANA_PASS)")
		rulesDir = flag.String("rules", "./rules",
			"directory of rule files (.json/.yaml/.yml), walked recursively")
		dryRun   = flag.Bool("dry-run", false, "print planned actions, mutate nothing")
		timeout  = flag.Duration("timeout", 30*time.Second, "per-request timeout")
		insecure = flag.Bool("insecure", false, "skip TLS verification (self-signed lab certs only)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)

	if *user == "" || *pass == "" {
		logger.Fatal("missing credentials: set KIBANA_USER/KIBANA_PASS or -user/-pass")
	}

	rules, err := rule.LoadDir(*rulesDir)
	if err != nil {
		logger.Fatalf("load rules: %v", err)
	}
	logger.Printf("loaded %d rule(s) from %s", len(rules), *rulesDir)

	client := kibana.New(*kibanaURL, *user, *pass, *timeout, *insecure)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	summary := syncer.Run(ctx, client, rules, *dryRun, logger)

	suffix := ""
	if *dryRun {
		suffix = " (dry-run: nothing applied)"
	}
	logger.Printf("sync complete%s: %s", suffix, summary)

	if summary.Failed > 0 {
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
