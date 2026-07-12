// Reconciles local rule definitions against the Detection Engine, one rule at a time.
package syncer

import (
	"context"
	"fmt"
	"log"

	"dac-sync/internal/kibana"
	"dac-sync/internal/rule"
)

type Action string

const (
	ActionCreate Action = "CREATE"
	ActionUpdate Action = "UPDATE"
)

type Summary struct {
	Created int
	Updated int
	Failed  int
}

func (s Summary) String() string {
	return fmt.Sprintf("created=%d updated=%d failed=%d", s.Created, s.Updated, s.Failed)
}

func Run(ctx context.Context, c *kibana.Client, rules []*rule.Rule, dryRun bool, logger *log.Logger) Summary {
	var s Summary
	for i, r := range rules {
		if err := ctx.Err(); err != nil {
			s.Failed += len(rules) - i
			logger.Printf("[ABORT      ] %v — %d rule(s) not attempted", err, len(rules)-i)
			break
		}

		action, err := reconcile(ctx, c, r, dryRun)
		if err != nil {
			s.Failed++
			logger.Printf("[FAIL       ] %s (%s): %v", r.RuleID, r.Path, err)
			continue
		}

		switch action {
		case ActionCreate:
			s.Created++
		case ActionUpdate:
			s.Updated++
		}
		verb := string(action)
		if dryRun {
			verb = "PLAN:" + verb
		}
		logger.Printf("[%-11s] %s  %q", verb, r.RuleID, r.Name)
	}
	return s
}

func reconcile(ctx context.Context, c *kibana.Client, r *rule.Rule, dryRun bool) (Action, error) {
	exists, err := c.RuleExists(ctx, r.RuleID)
	if err != nil {
		return "", fmt.Errorf("existence check: %w", err)
	}

	action := ActionCreate
	if exists {
		action = ActionUpdate
	}
	if dryRun {
		return action, nil
	}

	body, err := r.JSON()
	if err != nil {
		return "", err
	}
	if exists {
		if err := c.UpdateRule(ctx, body); err != nil {
			return "", fmt.Errorf("update: %w", err)
		}
	} else {
		if err := c.CreateRule(ctx, body); err != nil {
			return "", fmt.Errorf("create: %w", err)
		}
	}
	return action, nil
}
