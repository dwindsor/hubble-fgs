// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This package is an attempt (no pun intended) to provide a log of operations useful for
// troubleshooting. The main idea is to maintain a number of "attempts" (maxAttempts) so that they
// can be queries by a CLI or other means. The attempts can also be constructed out of multiple
// attempts. This is currently used by the mandate code, but it might be useful to use it for other
// packages as well.

package attempt

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
)

type InfoEntry struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

// An attempt to perform an operation
type Attempt struct {
	Op       string        `json:"op"`
	Info     []InfoEntry   `json:"info,omitempty"`
	Time     time.Time     `json:"time"`
	Duration time.Duration `json:"duration"`
	Result   Result        `json:"result"`
	Attempts []Attempt     `json:"attempts,omitempty"`
}

// Attempts is a log of attempts
//
// The Attempts field might hold a subset of all attempts (e.g., the last N attempts), so
// len(Attempts) is not necessarily equal to Total.
type Attempts struct {
	Total    int       `json:"total"`
	Failures int       `json:"failures"`
	Entries  []Attempt `json:"entries"`
}

func (as *Attempts) LastEntry() *Attempt {
	if len(as.Entries) == 0 {
		return nil
	}

	return new(as.Entries[len(as.Entries)-1])
}

type Logger interface {
	NewAttempt(op string) *InprAttempt

	logAttempt(a Attempt)
}

// in progress attempt
type InprAttempt struct {
	op   string
	time time.Time

	logger  Logger
	canNest bool

	inProgress atomic.Int32

	// mu protects the fields below. Sub-attempts may be completed
	// concurrently from multiple goroutines, which appends to attempts.
	mu       sync.Mutex
	info     []InfoEntry
	attempts []Attempt
	errCnt   int
}

func (a *InprAttempt) WithInfo(k, v string) *InprAttempt {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.info = append(a.info, InfoEntry{Key: k, Val: v})
	return a
}

func (a *InprAttempt) SetInfo(k, v string) {
	a.WithInfo(k, v)
}

func (a *InprAttempt) Complete(err error) error {
	if a.inProgress.Load() > 0 {
		return fmt.Errorf("cannot complete attempt: %d sub-attempts in progress", a.inProgress.Load())
	}
	if a.inProgress.Load() < 0 {
		return errors.New("attempt already completed")
	}

	var result Result
	if err != nil {
		result = Result{err: err}
	}

	a.inProgress.Store(-1)
	a.mu.Lock()
	info := slices.Clone(a.info)
	attempts := slices.Clone(a.attempts)
	a.mu.Unlock()
	a.logger.logAttempt(Attempt{
		Op:       a.op,
		Info:     info,
		Time:     a.time,
		Duration: time.Since(a.time),
		Result:   result,
		Attempts: attempts,
	})
	return nil
}

func (a *InprAttempt) NewAttempt(op string) *InprAttempt {
	if !a.canNest {
		panic("called NewAttempt on a non-nestible attempt")
	}

	a.inProgress.Add(1)
	return &InprAttempt{
		op:      op,
		time:    time.Now(),
		logger:  a,
		canNest: false,
	}
}

func (a *InprAttempt) logAttempt(c Attempt) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inProgress.Load() > 0 {
		a.inProgress.Add(-1)
	} else {
		logger.GetLogger().Error(fmt.Sprintf("invalid inProgress count when trying to log attempt: %d", a.inProgress.Load()))
	}

	a.attempts = append(a.attempts, c)
	if c.Result.err != nil {
		a.errCnt++
	}
}

func RunAttempt(att *InprAttempt, fn func() error) error {
	err := fn()
	att.Complete(err)
	return err
}
