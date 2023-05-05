package coordinatortest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/mocks"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type Helper struct {
	Coordinator *coordinator.Coordinator

	RuntimeManager      *mocks.RuntimeManager
	RuntimeErrorChannel chan error

	ConfigManager       *mocks.ConfigManager
	ConfigChangeChannel chan coordinator.ConfigChange
	ConfigErrorChannel  chan error
	ActionErrorChannel  chan error

	VarsManager      *mocks.VarsManager
	VarsChannel      chan []*transpiler.Vars
	VarsErrorChannel chan error

	Capability     *mocks.Capability
	UpgradeManager *mocks.UpgradeManager
	ReExecManager  *mocks.ReExecManager
	MonitorManager *mocks.MonitorManager
}

func NewHelper(
	t *testing.T,
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	specs component.RuntimeSpecs,
	isManaged bool) *coordinator.Coordinator {
	t.Helper()
	h := Helper{}

	// ReExec manager
	h.ReExecManager = mocks.NewReExecManager(t)

	// Upgrade manager
	mockUpgradeMgr := mocks.NewUpgradeManager(t)
	mockUpgradeMgr.EXPECT().Reload(mock.AnythingOfType("*config.Config")).Return(nil)

	// Runtime manager basic wiring
	mockRuntimeMgr := mocks.NewRuntimeManager(t)
	runtimeErrChan := make(chan error)
	mockRuntimeMgr.EXPECT().Errors().Return(runtimeErrChan)
	mockRuntimeMgr.EXPECT().
		Run(mock.Anything).
		RunAndReturn(func(_ctx context.Context) error {
			<-_ctx.Done()
			return _ctx.Err()
		}).
		Times(1)

	h.RuntimeManager = mockRuntimeMgr
	h.RuntimeErrorChannel = runtimeErrChan

	// Config manager
	mockConfigMgr := mocks.NewConfigManager(t)
	configErrChan := make(chan error)
	mockConfigMgr.EXPECT().Errors().Return(configErrChan)
	actionErrorChan := make(chan error)
	mockConfigMgr.EXPECT().ActionErrors().Return(actionErrorChan)
	configChangeChan := make(chan coordinator.ConfigChange)
	mockConfigMgr.EXPECT().Watch().Return(configChangeChan)
	mockConfigMgr.EXPECT().Run(mock.Anything).RunAndReturn(func(_ctx context.Context) error { <-_ctx.Done(); return _ctx.Err() }).Times(1)
	h.ConfigManager = mockConfigMgr
	h.ConfigErrorChannel = configErrChan
	h.ActionErrorChannel = actionErrorChan
	h.ConfigChangeChannel = configChangeChan

	// Vars manager
	mockVarsMgr := mocks.NewVarsManager(t)
	varsErrChan := make(chan error)
	mockVarsMgr.EXPECT().Errors().Return(varsErrChan)
	varsChan := make(chan []*transpiler.Vars)
	mockVarsMgr.EXPECT().Watch().Return(varsChan)
	mockVarsMgr.EXPECT().Run(mock.Anything).RunAndReturn(func(_ctx context.Context) error { <-_ctx.Done(); return _ctx.Err() }).Times(1)
	h.VarsManager = mockVarsMgr
	h.VarsChannel = varsChan
	h.VarsErrorChannel = varsErrChan

	// Capability
	mockCapability := mocks.NewCapability(t)
	mockCapability.EXPECT().
		Apply(mock.AnythingOfType("*transpiler.AST")).
		RunAndReturn(func(in interface{}) (interface{}, error) { return in, nil })
	h.Capability = mockCapability

	// Monitor manager
	mockMonitorMgr := mocks.NewMonitorManager(t)
	mockMonitorMgr.EXPECT().Reload(mock.AnythingOfType("*config.Config")).Return(nil)
	mockMonitorMgr.EXPECT().Enabled().Return(false)
	h.MonitorManager = mockMonitorMgr

	return coordinator.New(
		log,
		logp.InfoLevel,
		agentInfo,
		specs,
		h.ReExecManager,
		h.UpgradeManager,
		h.RuntimeManager,
		h.ConfigManager,
		h.VarsManager,
		h.Capability,
		h.MonitorManager,
		isManaged,
	)
}
