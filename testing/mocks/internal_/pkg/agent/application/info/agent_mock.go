// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Code generated by mockery v2.42.2. DO NOT EDIT.

package info

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// Agent is an autogenerated mock type for the Agent type
type Agent struct {
	mock.Mock
}

type Agent_Expecter struct {
	mock *mock.Mock
}

func (_m *Agent) EXPECT() *Agent_Expecter {
	return &Agent_Expecter{mock: &_m.Mock}
}

// AgentID provides a mock function with given fields:
func (_m *Agent) AgentID() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AgentID")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Agent_AgentID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AgentID'
type Agent_AgentID_Call struct {
	*mock.Call
}

// AgentID is a helper method to define mock.On call
func (_e *Agent_Expecter) AgentID() *Agent_AgentID_Call {
	return &Agent_AgentID_Call{Call: _e.mock.On("AgentID")}
}

func (_c *Agent_AgentID_Call) Run(run func()) *Agent_AgentID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_AgentID_Call) Return(_a0 string) *Agent_AgentID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_AgentID_Call) RunAndReturn(run func() string) *Agent_AgentID_Call {
	_c.Call.Return(run)
	return _c
}

// Headers provides a mock function with given fields:
func (_m *Agent) Headers() map[string]string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Headers")
	}

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func() map[string]string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	return r0
}

// Agent_Headers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Headers'
type Agent_Headers_Call struct {
	*mock.Call
}

// Headers is a helper method to define mock.On call
func (_e *Agent_Expecter) Headers() *Agent_Headers_Call {
	return &Agent_Headers_Call{Call: _e.mock.On("Headers")}
}

func (_c *Agent_Headers_Call) Run(run func()) *Agent_Headers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_Headers_Call) Return(_a0 map[string]string) *Agent_Headers_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_Headers_Call) RunAndReturn(run func() map[string]string) *Agent_Headers_Call {
	_c.Call.Return(run)
	return _c
}

// LogLevel provides a mock function with given fields:
func (_m *Agent) LogLevel() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for LogLevel")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Agent_LogLevel_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogLevel'
type Agent_LogLevel_Call struct {
	*mock.Call
}

// LogLevel is a helper method to define mock.On call
func (_e *Agent_Expecter) LogLevel() *Agent_LogLevel_Call {
	return &Agent_LogLevel_Call{Call: _e.mock.On("LogLevel")}
}

func (_c *Agent_LogLevel_Call) Run(run func()) *Agent_LogLevel_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_LogLevel_Call) Return(_a0 string) *Agent_LogLevel_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_LogLevel_Call) RunAndReturn(run func() string) *Agent_LogLevel_Call {
	_c.Call.Return(run)
	return _c
}

// RawLogLevel provides a mock function with given fields:
func (_m *Agent) RawLogLevel() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RawLogLevel")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Agent_RawLogLevel_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RawLogLevel'
type Agent_RawLogLevel_Call struct {
	*mock.Call
}

// RawLogLevel is a helper method to define mock.On call
func (_e *Agent_Expecter) RawLogLevel() *Agent_RawLogLevel_Call {
	return &Agent_RawLogLevel_Call{Call: _e.mock.On("RawLogLevel")}
}

func (_c *Agent_RawLogLevel_Call) Run(run func()) *Agent_RawLogLevel_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_RawLogLevel_Call) Return(_a0 string) *Agent_RawLogLevel_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_RawLogLevel_Call) RunAndReturn(run func() string) *Agent_RawLogLevel_Call {
	_c.Call.Return(run)
	return _c
}

// ReloadID provides a mock function with given fields: ctx
func (_m *Agent) ReloadID(ctx context.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ReloadID")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Agent_ReloadID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReloadID'
type Agent_ReloadID_Call struct {
	*mock.Call
}

// ReloadID is a helper method to define mock.On call
//   - ctx context.Context
func (_e *Agent_Expecter) ReloadID(ctx interface{}) *Agent_ReloadID_Call {
	return &Agent_ReloadID_Call{Call: _e.mock.On("ReloadID", ctx)}
}

func (_c *Agent_ReloadID_Call) Run(run func(ctx context.Context)) *Agent_ReloadID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *Agent_ReloadID_Call) Return(_a0 error) *Agent_ReloadID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_ReloadID_Call) RunAndReturn(run func(context.Context) error) *Agent_ReloadID_Call {
	_c.Call.Return(run)
	return _c
}

// SetLogLevel provides a mock function with given fields: ctx, level
func (_m *Agent) SetLogLevel(ctx context.Context, level string) error {
	ret := _m.Called(ctx, level)

	if len(ret) == 0 {
		panic("no return value specified for SetLogLevel")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, level)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Agent_SetLogLevel_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetLogLevel'
type Agent_SetLogLevel_Call struct {
	*mock.Call
}

// SetLogLevel is a helper method to define mock.On call
//   - ctx context.Context
//   - level string
func (_e *Agent_Expecter) SetLogLevel(ctx interface{}, level interface{}) *Agent_SetLogLevel_Call {
	return &Agent_SetLogLevel_Call{Call: _e.mock.On("SetLogLevel", ctx, level)}
}

func (_c *Agent_SetLogLevel_Call) Run(run func(ctx context.Context, level string)) *Agent_SetLogLevel_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Agent_SetLogLevel_Call) Return(_a0 error) *Agent_SetLogLevel_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_SetLogLevel_Call) RunAndReturn(run func(context.Context, string) error) *Agent_SetLogLevel_Call {
	_c.Call.Return(run)
	return _c
}

// Snapshot provides a mock function with given fields:
func (_m *Agent) Snapshot() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Snapshot")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Agent_Snapshot_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Snapshot'
type Agent_Snapshot_Call struct {
	*mock.Call
}

// Snapshot is a helper method to define mock.On call
func (_e *Agent_Expecter) Snapshot() *Agent_Snapshot_Call {
	return &Agent_Snapshot_Call{Call: _e.mock.On("Snapshot")}
}

func (_c *Agent_Snapshot_Call) Run(run func()) *Agent_Snapshot_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_Snapshot_Call) Return(_a0 bool) *Agent_Snapshot_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_Snapshot_Call) RunAndReturn(run func() bool) *Agent_Snapshot_Call {
	_c.Call.Return(run)
	return _c
}

// Unprivileged provides a mock function with given fields:
func (_m *Agent) Unprivileged() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Unprivileged")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Agent_Unprivileged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Unprivileged'
type Agent_Unprivileged_Call struct {
	*mock.Call
}

// Unprivileged is a helper method to define mock.On call
func (_e *Agent_Expecter) Unprivileged() *Agent_Unprivileged_Call {
	return &Agent_Unprivileged_Call{Call: _e.mock.On("Unprivileged")}
}

func (_c *Agent_Unprivileged_Call) Run(run func()) *Agent_Unprivileged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_Unprivileged_Call) Return(_a0 bool) *Agent_Unprivileged_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_Unprivileged_Call) RunAndReturn(run func() bool) *Agent_Unprivileged_Call {
	_c.Call.Return(run)
	return _c
}

// Version provides a mock function with given fields:
func (_m *Agent) Version() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Version")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Agent_Version_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Version'
type Agent_Version_Call struct {
	*mock.Call
}

// Version is a helper method to define mock.On call
func (_e *Agent_Expecter) Version() *Agent_Version_Call {
	return &Agent_Version_Call{Call: _e.mock.On("Version")}
}

func (_c *Agent_Version_Call) Run(run func()) *Agent_Version_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Agent_Version_Call) Return(_a0 string) *Agent_Version_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Agent_Version_Call) RunAndReturn(run func() string) *Agent_Version_Call {
	_c.Call.Return(run)
	return _c
}

// NewAgent creates a new instance of Agent. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAgent(t interface {
	mock.TestingT
	Cleanup(func())
}) *Agent {
	mock := &Agent{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
