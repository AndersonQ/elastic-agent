// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backoff

import (
	"time"
)

// ExpBackoff implements an exponential backoff strategy, where it initially
// waits for a specific duration and then exponentially increases the wait time.
// This increment continues until it reaches a predefined maximum value.
// Resetting the backoff will reset the timer for the next sleep to the
// initial backoff duration.
type ExpBackoff struct {
	duration time.Duration
	done     <-chan struct{}

	init time.Duration
	max  time.Duration

	last time.Time
}

// NewExpBackoff returns a new exponential backoff. It will run indefinitely,
// unless the 'done' channel is closed.
func NewExpBackoff(done <-chan struct{}, init, max time.Duration) Backoff {
	return &ExpBackoff{
		duration: init,
		done:     done,
		init:     init,
		max:      max,
	}
}

// Reset resets the duration of the backoff.
func (b *ExpBackoff) Reset() {
	b.duration = b.init
}

func (b *ExpBackoff) NextWait() time.Duration {
	nextWait := b.duration
	nextWait *= 2
	if nextWait > b.max {
		nextWait = b.max
	}
	return nextWait
}

// Wait block until either the timer is completed or channel is done.
// It returns true if the timer hasn't completed yet.
func (b *ExpBackoff) Wait() bool {
	b.duration = b.NextWait()

	select {
	case <-b.done:
		return false
	case <-time.After(b.duration):
		b.last = time.Now()
		return true
	}
}
