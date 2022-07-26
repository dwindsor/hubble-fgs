//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kfree

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/vtuple"
	api "github.com/isovalent/hubble-fgs/pkg/api/kfreeapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"

	stt "github.com/cilium/tetragon/pkg/stacktracetree"
)

var (
	ksym *ksyms.Ksyms
)

func handleKfreeSkb(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgKfreeSkb{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read kfree_skb msg")
		return nil, err
	}

	msgUnix := msgToKfreeSkbUnix(&m)

	if packetdropCfg != nil && packetdropCfg.FilterStr != "" {
		if !packetdropCfg.Filter.FilterFn(&msgUnix.Tuple) {
			return nil, nil
		}
	}

	stt_lbl := []string{vtuple.StringRep(&msgUnix.Tuple)}
	s := stt.SttFromCalltrace(msgUnix.Calltrace, stt_lbl)
	observer.SensorManager.STTManager.Insert("packet-drop", s)

	return nil, nil
}

func init() {
	AddKfree()
}

func AddKfree() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_KFREE_SKB, handleKfreeSkb)
	ksym, _ = ksyms.NewKsyms(option.Config.ProcFS)
}
