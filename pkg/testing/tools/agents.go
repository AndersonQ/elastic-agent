// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

// GetAgentByHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func GetAgentByHostnameFromList(client *kibana.Client, hostname string) (*kibana.AgentExisting, error) {
	listAgentsResp, err := client.ListAgents(context.Background(), kibana.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}

	for _, item := range listAgentsResp.Items {
		agentHostname := item.LocalMetadata.Host.Hostname
		if agentHostname == hostname {
			return &item, nil
		}
	}

	return nil, fmt.Errorf("unable to find agent with hostname [%s]", hostname)
}

func GetAgentStatus(client *kibana.Client) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}

	return agent.Status, nil
}

func GetAgentVersion(client *kibana.Client) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}

	return agent.Agent.Version, err
}

func UnEnrollAgent(client *kibana.Client) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(client, hostname)
	if err != nil {
		return err
	}

	unEnrollAgentReq := kibana.UnEnrollAgentRequest{
		ID:     agentID,
		Revoke: true,
	}
	_, err = client.UnEnrollAgent(context.Background(), unEnrollAgentReq)
	if err != nil {
		return fmt.Errorf("unable to unenroll agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func GetAgentIDByHostname(client *kibana.Client, hostname string) (string, error) {
	agent, err := GetAgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}
	return agent.Agent.ID, nil
}

func UpgradeAgent(client *kibana.Client, version string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(client, hostname)
	if err != nil {
		return err
	}

	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
	}
	_, err = client.UpgradeAgent(context.Background(), upgradeAgentReq)
	if err != nil {
		return fmt.Errorf("unable to upgrade agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func GetDefaultFleetServerURL(client *kibana.Client) (string, error) {
	req := kibana.ListFleetServerHostsRequest{}
	resp, err := client.ListFleetServerHosts(context.Background(), req)
	if err != nil {
		return "", fmt.Errorf("unable to list fleet server hosts: %w", err)
	}

	for _, item := range resp.Items {
		if item.IsDefault {
			hostURLs := item.HostURLs
			if len(hostURLs) > 0 {
				return hostURLs[0], nil
			}
		}
	}

	return "", errors.New("unable to determine default fleet server host")
}

// WaitForAgentHealthy will keep checking the agent state until it becomes healthy
// ot the timeout is exceeded. If the agent becomes health, it returns true, if
// not the test is marked as failed and false is returned.
// The timeout is the context deadline, if defined, or set to 2 minutes.
func WaitForAgentHealthy(ctx context.Context, t *testing.T, c client.Client) bool {
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

// WaitForAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func WaitForAgentStatus(t *testing.T, client *kibana.Client, expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := GetAgentStatus(client)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}

		t.Logf("Agent status: %s", currentStatus)
		return false
	}
}
