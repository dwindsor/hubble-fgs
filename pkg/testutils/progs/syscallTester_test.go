//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package progs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSyscallTesterCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := StartSyscallTester(t, ctx)
	res, err := st.Command("ping")
	require.Equal(t, res, "pong")
	require.Nil(t, err)
	err = st.Stop()
	require.Nil(t, err)
	err = st.Cmd.Wait()
	require.Nil(t, err)
}

func TestSyscallTesterSigkill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := StartSyscallTester(t, ctx)
	st.Process().Kill()
	err := st.Stop()
	require.Nil(t, err)
	err = st.Cmd.Wait()
	require.NotNil(t, err)
	require.Equal(t, err.Error(), "signal: killed")
}

func TestSyscallTesterTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	st := StartSyscallTester(t, ctx)
	err := st.Cmd.Wait()
	require.NotNil(t, err.Error())
	// NB: timeout will result in a kill
	require.Equal(t, err.Error(), "signal: killed")
}
