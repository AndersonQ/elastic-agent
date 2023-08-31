// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package check

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

// ConnectedToFleet checks if the agent defined in the fixture is connected to
// Fleet Server. It uses assert.Eventually and if it fails the last error will
// be printed. It returns if the agent is connected to Fleet Server or not.
func ConnectedToFleet(t *testing.T, fixture *integrationtest.Fixture, timeout time.Duration) bool {
	t.Helper()

	var err error
	var agentStatus integrationtest.AgentStatusOutput
	assertFn := func() bool {
		agentStatus, err = fixture.ExecStatus(context.Background())
		return agentStatus.FleetState == int(cproto.State_HEALTHY)
	}

	connected := assert.Eventually(t, assertFn, timeout, 5*time.Second,
		"want fleet state %s, got %s. agent status: %v",
		cproto.State_HEALTHY, cproto.State(agentStatus.FleetState), agentStatus)

	if !connected && err != nil {
		t.Logf("agent isn't connected to fleet-server: last error from agent status command: %v",
			err)
	}

	return connected
}

// WaitForLocalAgentHealthy will keep checking the agent state until it becomes healthy
// ot the timeout is exceeded. If the agent becomes health, it returns true, if
// not the test is marked as failed and false is returned.
// The timeout is the context deadline, if defined, or set to 2 minutes.
func WaitForLocalAgentHealthy(ctx context.Context, t *testing.T, c client.Client) bool {
	// https://github.com/elastic/elastic-agent/pull/3265
	timeout := 2 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	return assert.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		return state.State == cproto.State_HEALTHY
	}, timeout, 10*time.Second, "Agent never became healthy")
}

// FleetAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func FleetAgentStatus(t *testing.T, client *kibana.Client, expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := tools.GetAgentStatus(client)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}

		t.Logf("Agent fleet status: %s", currentStatus)
		return false
	}
}
