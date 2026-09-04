// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package exec

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecParse(t *testing.T) {
	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}

	exec := processapi.MsgExec{}
	filename := []byte("/bin/krava")
	cwd := []byte("/home/krava")

	// Following tests prepare reader with MsgExec event plus additional data
	// that follows it - filename, arguments, cwd
	//
	// The filename could be in form of data event or string. The arguments
	// data is optional and can be only in form of data event. This setup is
	// reflected in MsgExec::Flags.
	//
	// Based on the MsgExec::Flags the execParse function parses out MsgProcess
	// object.

	var err error

	t.Run("Empty args", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - no args
		// - cwd (string)

		exec.Flags = 0
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = 0
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(cwd), process.Cwd)
		assert.Empty(t, process.Args)
	})

	t.Run("Empty args and cwd", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - no args
		// - no cwd

		exec.Flags = 0
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = 0
		exec.SizeCwd = 0

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Empty(t, process.Args)
		assert.Empty(t, process.Cwd)
	})

	t.Run("Filename as data event", func(t *testing.T) {
		observer.DataPurge()

		// - filename (data event)
		// - no args
		// - cwd (string)

		id := dataapi.DataEventId{Pid: 1, Time: 1}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(filename[:])), Id: id}
		err = observer.DataAdd(id, filename)
		require.NoError(t, err)

		exec.Flags = api.EventDataFilename
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + binary.Size(desc) + len(cwd))
		exec.SizePath = uint16(binary.Size(desc))
		exec.SizeArgs = 0
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, string(cwd), process.Cwd)
		assert.Empty(t, process.Args)
	})

	t.Run("Args as data event", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - args (data event)
		// - cwd (string)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0)

		id := dataapi.DataEventId{Pid: 1, Time: 2}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id}
		err = observer.DataAdd(id, args)
		require.NoError(t, err)

		exec.Flags = api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + binary.Size(desc) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(binary.Size(desc))
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, "arg1 arg2", process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	t.Run("Empty last arg", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - args (string), last one empty
		// - cwd (string)

		// BPF strips the trailing '\0', so the one left ends "arg1"
		// and starts the empty argument.
		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0)

		exec.Flags = 0
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + len(args) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(len(args))
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, args)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, `arg1 ""`, process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	t.Run("Empty last arg as data event", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - args (data event), last one empty
		// - cwd (string)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 0)

		id := dataapi.DataEventId{Pid: 1, Time: 2}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id}
		err = observer.DataAdd(id, args)
		require.NoError(t, err)

		exec.Flags = api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + binary.Size(desc) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(binary.Size(desc))
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, `arg1 ""`, process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	t.Run("Filename and args as data event", func(t *testing.T) {
		observer.DataPurge()

		// - filename (data event)
		// - args (data event)
		// - cwd (string)

		id1 := dataapi.DataEventId{Pid: 1, Time: 1}
		desc1 := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(filename[:])), Id: id1}
		err = observer.DataAdd(id1, filename)
		require.NoError(t, err)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0)

		id2 := dataapi.DataEventId{Pid: 1, Time: 2}
		desc2 := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id2}
		err = observer.DataAdd(id2, args)
		require.NoError(t, err)

		exec.Flags = api.EventDataFilename | api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + binary.Size(desc1) + binary.Size(desc2) + len(cwd))
		exec.SizePath = uint16(binary.Size(desc1))
		exec.SizeArgs = uint16(binary.Size(desc2))
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, desc1)
		binary.Write(&buf, binary.LittleEndian, desc2)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, "arg1 arg2", process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	t.Run("Filename and args as non-utf8", func(t *testing.T) {
		observer.DataPurge()

		// - filename (non-utf8)
		// - args (data event, non-utf8)
		// - cwd (string)

		var args []byte
		args = append(args, '\xc3', '\x28', 0, 'a', 'r', 'g', '2', 0)
		filename := []byte{'p', 'i', 'z', 'z', 'a', '-', '\xc3', '\x28'}
		cwd := []byte{'/', 'h', 'o', 'm', 'e', '/', '\xc3', '\x28'}

		id := dataapi.DataEventId{Pid: 1, Time: 2}
		desc := dataapi.DataEventDesc{Error: 0, Pad: 0, Leftover: 0, Size: uint32(len(args[:])), Id: id}
		err = observer.DataAdd(id, args)
		require.NoError(t, err)

		exec.Flags = api.EventDataArgs
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + binary.Size(desc) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(binary.Size(desc))
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, desc)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, strutils.UTF8FromBPFBytes(filename), process.Filename)
		assert.Equal(t, "�( arg2", process.Args)
		assert.Equal(t, strutils.UTF8FromBPFBytes(cwd), process.Cwd)
	})

	t.Run("Filename with api.EventErrorFilename", func(t *testing.T) {
		observer.DataPurge()

		// - filename (api.EventErrorFilename)
		// - no args
		// - cwd (string)

		exec.Flags = api.EventErrorFilename
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(cwd))
		exec.SizePath = 0
		exec.SizeArgs = 0
		exec.SizeCwd = uint16(len(cwd))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, "<enomem>", process.Filename)
		assert.Equal(t, string(cwd), process.Cwd)
		assert.Empty(t, process.Args)
	})

	t.Run("Filename, args, cwd and envs", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - args (string)
		// - cwd (string)
		// - envs (string)

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2')

		var envs []byte
		envs = append(envs, 'A', '=', '1', 0, 'B', '=', '2')

		exec.Flags = api.EventErrorFilename
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + len(args) + len(cwd) + len(envs))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(len(args))
		exec.SizeCwd = uint16(len(cwd))
		exec.SizeEnvs = uint16(len(envs))

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, args)
		binary.Write(&buf, binary.LittleEndian, cwd)
		binary.Write(&buf, binary.LittleEndian, envs)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, []string{"A=1", "B=2"}, process.Envs)

		assert.Equal(t, "arg1 arg2", process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	t.Run("Filename, args, cwd and zero envs", func(t *testing.T) {
		observer.DataPurge()

		// - filename (string)
		// - args (string)
		// - cwd (string)
		// - empty envs

		var args []byte
		args = append(args, 'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2')

		exec.Flags = api.EventErrorFilename
		exec.Size = uint32(processapi.MSG_SIZEOF_EXECVE + len(filename) + len(args) + len(cwd))
		exec.SizePath = uint16(len(filename))
		exec.SizeArgs = uint16(len(args))
		exec.SizeCwd = uint16(len(cwd))
		exec.SizeEnvs = 0

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, exec)
		binary.Write(&buf, binary.LittleEndian, filename)
		binary.Write(&buf, binary.LittleEndian, args)
		binary.Write(&buf, binary.LittleEndian, cwd)

		reader := bytes.NewReader(buf.Bytes())

		process, err := execParse(reader)
		require.NoError(t, err)

		assert.Equal(t, string(filename), process.Filename)
		assert.Equal(t, []string(nil), process.Envs)

		assert.Equal(t, "arg1 arg2", process.Args)
		assert.Equal(t, string(cwd), process.Cwd)
	})

	observer.DataPurge()
}
