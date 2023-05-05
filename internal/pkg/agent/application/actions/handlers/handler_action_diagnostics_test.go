package handlers

import (
	"bytes"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Refer to https://vektra.github.io/mockery/installation/ to check how to install mockery binary
//
//go:generate mockery --name coordinator.Coordinator
func TestPolicyChangeHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	log := logger.NewToBuffer("TestPolicyChangeHandler", buf)
	h := Diagnostics{}

	capabilities.Capability()
}
