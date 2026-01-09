// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package parsertest

//
// A minimal "Observer" implementation for figuring out what we need for
// low-level testing. Very likely we can modify Observer to work well here.
// Just need a hook to skip all handlers and process the event directly.
//

type EventSubscription struct {
	Op          byte
	Events      chan []byte
	Unsubscribe func()
}

func (ed *EventDispatcher) Subscribe(op byte) *EventSubscription {
	ed.Lock()
	defer ed.Unlock()

	id := ed.nextSubId
	ed.nextSubId++
	events := make(chan []byte, 32)

	if ed.subs == nil {
		ed.subs = make(map[int]*EventSubscription)
	}

	sub := &EventSubscription{
		Op:     op,
		Events: events,
		Unsubscribe: func() {
			ed.Lock()
			delete(ed.subs, id)
			ed.Unlock()
		},
	}
	ed.subs[id] = sub

	return sub
}

func (ed *EventDispatcher) UnsubscribeAll() {
	ed.Lock()
	defer ed.Unlock()

	for _, sub := range ed.subs {
		close(sub.Events)
	}
	ed.subs = nil
}
