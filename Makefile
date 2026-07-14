.PHONY: test check-pipeline ci

# Local, credential-free checks: Go tests, the JS parser's own test suite,
# and generate-pipeline.js's staleness + smoke-test checks (which run
# unconditionally, not just under --check -- see generate-pipeline.js).
test:
	go test ./...
	node cribl/winxml_to_ecs.js
	node cribl/generate-pipeline.js --check
	node cribl/generate-assets-lookup.js --check

# Requires a running Cribl instance and CRIBL_PW (see scripts/check-pipeline-drift.sh).
# Proves the pipeline actually deployed matches what the tests above checked,
# which "node cribl/winxml_to_ecs.js" alone cannot -- see CHANGES.md Phase 6.
check-pipeline:
	./scripts/check-pipeline-drift.sh

ci: test
