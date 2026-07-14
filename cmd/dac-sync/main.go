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

	"dac-sync/internal/elastic"
	"dac-sync/internal/kibana"
	"dac-sync/internal/preflight"
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

		elasticURL = flag.String("elastic", envOr("ELASTIC_URL", "http://localhost:9200"),
			"Elasticsearch base URL, used for preflight field-mapping checks")
		elasticUser = flag.String("elastic-user", envOr("ELASTIC_USER", "elastic"),
			"Elasticsearch basic auth user (or env ELASTIC_USER)")
		elasticPass = flag.String("elastic-pass", os.Getenv("ELASTIC_PASSWORD"),
			"Elasticsearch basic auth password (or env ELASTIC_PASSWORD)")
		contractPath = flag.String("field-contract", "./schema/field-contract.yaml",
			"path to the field-type contract preflight validates rules against")
		doPreflight = flag.Bool("preflight", true,
			"validate each rule's referenced fields against the live Elasticsearch mapping before syncing")
		preflightStrict = flag.Bool("preflight-strict", false,
			"also fail preflight on a mapped-but-never-populated field (not just warn)")
		skipPreflight = flag.Bool("skip-preflight", false,
			"disable preflight entirely (equivalent to -preflight=false)")
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

	var pf *syncer.PreflightConfig
	if *doPreflight && !*skipPreflight {
		if *elasticPass == "" {
			logger.Fatal("preflight is enabled but missing Elasticsearch credentials: set ELASTIC_PASSWORD or -elastic-pass (or pass -skip-preflight)")
		}
		contract, err := preflight.LoadContract(*contractPath)
		if err != nil {
			logger.Fatalf("load field contract: %v", err)
		}
		esClient := elastic.New(*elasticURL, *elasticUser, *elasticPass, *timeout, *insecure)
		pf = &syncer.PreflightConfig{Client: esClient, Contract: contract, Strict: *preflightStrict}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	summary := syncer.Run(ctx, client, rules, *dryRun, pf, logger)

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
