package eventchecker

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

import (
	"testing"
)

// Logger interface to be used in checkers
type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

// TestPrefixLogger is a simple wrapper of testing.T that allows to log with a prefix
type TestPrefixLogger struct {
	Prefix string
	T      *testing.T
}

func (l *TestPrefixLogger) Log(args ...interface{}) {
	newargs := append([]interface{}{l.Prefix}, args...)
	l.T.Log(newargs...)
}

func (l *TestPrefixLogger) Fatal(args ...interface{}) {
	newargs := append([]interface{}{l.Prefix}, args...)
	l.T.Fatal(newargs...)
}

func (l *TestPrefixLogger) Logf(format string, args ...interface{}) {
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.T.Logf(newfmt, newargs...)
}

func (l *TestPrefixLogger) Fatalf(format string, args ...interface{}) {
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.T.Fatalf(newfmt, newargs...)
}
