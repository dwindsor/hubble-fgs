// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package attempt

import "time"

const (
	maxAttempts = 32
)

type Log struct {
	total    int
	failures int
	last     [maxAttempts]Attempt
}

func (l *Log) add(a Attempt) {
	idx := l.total % maxAttempts
	l.last[idx] = a

	l.total++
	if a.Result.err != nil {
		l.failures++
	}
}

func NewLog() *Log {
	return &Log{}
}

func (l *Log) NewAttempt(op string) *InprAttempt {
	return &InprAttempt{
		op:      op,
		time:    time.Now(),
		logger:  l,
		canNest: true,
	}
}

func (l *Log) logAttempt(a Attempt) {
	l.add(a)
}

func (l *Log) Attempts() Attempts {
	var ret Attempts
	ret.Total = l.total
	ret.Failures = l.failures

	n := min(l.total, maxAttempts)
	idx0 := l.total - n
	for i := 0; i < n; i++ {
		idx := (idx0 + i) % maxAttempts
		ret.Entries = append(ret.Entries, l.last[idx])
	}

	return ret
}
