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
	"github.com/sirupsen/logrus"
)

// Logger interface to be used in checkers
type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

// TestPrefixLogger is a simple wrapper of Logger that allows to log with a prefix
type PrefixLogger struct {
	Prefix string
	Logger Logger
}

func (l *PrefixLogger) Log(args ...interface{}) {
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Log(newargs...)
}

func (l *PrefixLogger) Fatal(args ...interface{}) {
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Fatal(newargs...)
}

func (l *PrefixLogger) Logf(format string, args ...interface{}) {
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Logf(newfmt, newargs...)
}

func (l *PrefixLogger) Fatalf(format string, args ...interface{}) {
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Fatalf(newfmt, newargs...)
}

type LogrusLogger struct {
	L *logrus.Logger
}

func (l *LogrusLogger) Log(args ...interface{}) {
	l.L.Log(logrus.InfoLevel, args...)
}

func (l *LogrusLogger) Fatal(args ...interface{}) {
	l.L.Fatal(args...)
}

func (l *LogrusLogger) Logf(format string, args ...interface{}) {
	l.L.Logf(logrus.InfoLevel, format, args...)
}

func (l *LogrusLogger) Fatalf(format string, args ...interface{}) {
	l.L.Fatalf(format, args...)
}
