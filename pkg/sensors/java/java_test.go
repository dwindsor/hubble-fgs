// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein, and the intellectual and technical
// concepts contained herein, are proprietary to Isovalent Inc. and its suppliers.

package java

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	api "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestValidateJavaPolicy(t *testing.T) {
	class := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0}
	valid := &api.JavaPolicySpec{
		Executables: []string{"/opt/jdk/bin/java"},
		Patches:     []api.JavaClassPatch{{Signature: "Lexample/Handler;", Replacement: class, Rollback: class}},
	}
	if err := validate(valid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	bad := *valid
	bad.Executables = []string{"java"}
	if err := validate(&bad); err == nil {
		t.Fatal("relative executable accepted")
	}
	bad = *valid
	bad.Patches = append(bad.Patches, bad.Patches[0])
	if err := validate(&bad); err == nil {
		t.Fatal("duplicate class signature accepted")
	}
}

func TestCurrentProcessIdentity(t *testing.T) {
	identity, err := readProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if identity.pid != os.Getpid() || identity.executable == "" || identity.startTicks == 0 {
		t.Fatalf("incomplete process identity: %+v", identity)
	}
}

func TestContainsAllArgTokens(t *testing.T) {
	cmdline := []byte("java\x00org.jboss.modules.Main\x00-Dservice=vmanage\x00")
	if !containsAllArgTokens(cmdline, []string{"org.jboss.modules.Main", "service=vmanage"}) {
		t.Fatal("expected all argument fragments to match")
	}
	if containsAllArgTokens(cmdline, []string{"org.jboss.modules.Main", "JobScheduler"}) {
		t.Fatal("unexpected argument fragment match")
	}
	if containsAllArgTokens(cmdline, []string{""}) {
		t.Fatal("empty argument fragment matched")
	}
}

func TestManifestEncodesReplacementAndRollback(t *testing.T) {
	patches := []api.JavaClassPatch{{
		Signature:   "Lexample/Handler;",
		Replacement: []byte{0xca, 0xfe, 0xba, 0xbe, 1},
		Rollback:    []byte{0xca, 0xfe, 0xba, 0xbe, 2},
	}}
	for _, tc := range []struct {
		rollback bool
		want     byte
	}{{false, 1}, {true, 2}} {
		manifest, err := manifest(patches, tc.rollback)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(manifest, []byte(manifestMagic)) {
			t.Fatal("manifest magic missing")
		}
		i := len(manifestMagic)
		if got := binary.BigEndian.Uint32(manifest[i : i+4]); got != 1 {
			t.Fatalf("record count = %d", got)
		}
		i += 4
		sigLen := int(binary.BigEndian.Uint16(manifest[i : i+2]))
		dataLen := int(binary.BigEndian.Uint32(manifest[i+2 : i+6]))
		i += 6
		if string(manifest[i:i+sigLen]) != patches[0].Signature {
			t.Fatal("wrong class signature")
		}
		i += sigLen
		if dataLen != 5 || manifest[i+dataLen-1] != tc.want {
			t.Fatalf("wrong class bytes in manifest: %v", manifest[i:i+dataLen])
		}
	}
}
