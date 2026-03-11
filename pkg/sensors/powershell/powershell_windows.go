// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package powershell

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"unsafe"

	"github.com/cilium/tetragon/pkg/observer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

/* =========================
   WEVTAPI minimal wrappers
   ========================= */

var (
	modWevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
	evtCallbackPtr   uintptr // keep the callback alive
	psEventXMLCh     = make(chan string, 256)
	reEventID        = regexp.MustCompile(`<EventID[^>]*>(\d+)</EventID>`)
)

const (
	// Subscribe flags
	EvtSubscribeToFutureEvents = 1

	// Render flags
	EvtRenderEventXml = 1

	// Callback action codes
	EvtSubscribeActionError   = 0
	EvtSubscribeActionDeliver = 1
)

// EnableScriptBlockLogging sets the registry policy keys under HKLM to turn on
// PowerShell Script Block Logging (Event ID 4104).
// Requires: Administrator privileges.
func EnableScriptBlockLogging() error {
	const policyPath = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

	// Open HKLM\...\ScriptBlockLogging (create if missing)
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyPath, registry.SET_VALUE|registry.READ)
	if err != nil {
		return fmt.Errorf("open/create policy key failed: %w", err)
	}
	defer k.Close()

	// Enable script block logging
	if err := k.SetDWordValue("EnableScriptBlockLogging", 1); err != nil {
		return fmt.Errorf("set EnableScriptBlockLogging failed: %w", err)
	}

	// Optional: enable invocation logging (more verbose; includes invocation info)
	// Commented by default. Uncomment if you want it.
	// if err := k.SetDWordValue("EnableScriptBlockInvocationLogging", 1); err != nil {
	//     return fmt.Errorf("set EnableScriptBlockInvocationLogging failed: %w", err)
	// }

	// If SuppressScriptBlockLogging exists, remove it to avoid suppressing logs
	_ = k.DeleteValue("SuppressScriptBlockLogging")

	return nil
}

// DisableScriptBlockLogging removes/sets values to effectively turn off script block logging.
// Requires: Administrator privileges.
func DisableScriptBlockLogging() error {
	const policyPath = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

	// Try to open the key (do not create on disable)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		// If it doesn't exist, consider it already disabled
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open policy key failed: %w", err)
	}
	defer k.Close()

	// Set EnableScriptBlockLogging to 0 (or delete the value)
	// Deleting reverts to "not configured"; setting 0 explicitly disables.
	if err := k.SetDWordValue("EnableScriptBlockLogging", 0); err != nil {
		// fall back to delete
		_ = k.DeleteValue("EnableScriptBlockLogging")
	}

	// Disable invocation logging if present
	if err := k.SetDWordValue("EnableScriptBlockInvocationLogging", 0); err != nil {
		_ = k.DeleteValue("EnableScriptBlockInvocationLogging")
	}

	// Optionally, explicitly suppress logging
	// _ = k.SetDWordValue("SuppressScriptBlockLogging", 1)

	return nil
}

func evtRenderXML(h windows.Handle) (string, error) {
	var used, props uint32
	// Probe buffer size
	r0, _, e1 := procEvtRender.Call(
		0,
		uintptr(h),
		uintptr(EvtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&props)),
	)
	if r0 == 0 {
		// Expect ERROR_INSUFFICIENT_BUFFER here
		if errno, ok := e1.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", e1
		}
	}
	buf := make([]uint16, used/2)
	r0, _, e1 = procEvtRender.Call(
		0,
		uintptr(h),
		uintptr(EvtRenderEventXml),
		uintptr(used),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&props)),
	)
	if r0 == 0 {
		return "", e1
	}
	return windows.UTF16ToString(buf), nil
}

func evtClose(h windows.Handle) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(uintptr(h))
	}
}

/* =========================
   Subscribe with CALLBACK
   ========================= */

// evtSubscribeWithCallback subscribes to the given channel/query and registers a stdcall callback.
// NOTE: The callback must be fast—do not block. We push XML into a buffered channel for processing.
func evtSubscribeWithCallback(channel, query string) (windows.Handle, error) {
	chW, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	qW, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}

	// Build the stdcall-compatible function pointer.
	cb := windows.NewCallback(func(action, userCtx, evt uintptr) uintptr {
		switch action {
		case EvtSubscribeActionDeliver:
			// evt is an EVT_HANDLE valid only during the callback.
			h := windows.Handle(evt)

			// Render to XML inside the callback.
			if xml, err := evtRenderXML(h); err == nil {
				// Non-blocking send; drop if channel is full to avoid stalling the callback.
				select {
				case psEventXMLCh <- xml:
				default:
					// drop on overload; consider metrics/logging if you need loss visibility
				}
			} else {
				// You may log, but avoid heavy work here.
			}

			// You MUST close the event handle before returning.
			evtClose(h)

		case EvtSubscribeActionError:
			// evt is actually a Win32 error code in this case (not a handle).
			status := uint32(evt)
			// Keep it very light here as well.
			log.Printf("EvtSubscribe ERROR: 0x%08X", status)
		}
		return 0
	})

	// Keep the callback pointer alive for the lifetime of the subscription.
	evtCallbackPtr = cb

	// session=NULL, signalEvent=NULL, bookmark=NULL, context=NULL, callback=cb, flags=EvtSubscribeToFutureEvents
	r0, _, e1 := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(chW)),
		uintptr(unsafe.Pointer(qW)),
		0,
		0,
		cb,
		uintptr(EvtSubscribeToFutureEvents),
	)
	h := windows.Handle(r0)
	if h == 0 {
		if e1 != windows.ERROR_SUCCESS {
			return 0, e1
		}
		return 0, fmt.Errorf("EvtSubscribe failed")
	}

	// Also tell GC this callback is still needed (extra safety).
	runtime.KeepAlive(cb)
	return h, nil
}

/* =========================
   Tail PowerShell Operational (callback)
   ========================= */

func tailPSEventsCallback() (cancel func(), err error) {
	channel := "Microsoft-Windows-PowerShell/Operational"
	// 4103 = Module logging, 4104 = Script block logging, 4105/4106 = Engine start/stop
	query := "*[System[(EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106)]]"

	sub, err := evtSubscribeWithCallback(channel, query)
	if err != nil {
		return nil, fmt.Errorf("PowerShell Operational subscription failed: %w", err)
	}

	// Consumer goroutine: parse/print the XML (kept out of the callback for responsiveness).
	done := make(chan struct{})
	go func() {
		log.Println("Tailing Microsoft-Windows-PowerShell/Operational via CALLBACK (4103/4104/4105/4106)...")
		for {
			select {
			case xml := <-psEventXMLCh:
				eid := firstMatch(reEventID, xml)

				if eid == "4103" {
					event, err := parseEvent(xml)
					if err != nil {
						fmt.Println("Parse error:", err)
						return
					}

					pwshEvent, err := toPowerShellEvent(event)
					if err != nil {
						fmt.Println("Conversion error:", err)
						continue
					}
					observer.AllListeners(pwshEvent)

				}
				if eid == "4104" {
					event, err := parseEvent(xml)
					if err != nil {
						fmt.Println("Parse error:", err)
						return
					}

					pwshEvent, err := toPowerShellCmdEvent(event)
					if err != nil {
						fmt.Println("Conversion error:", err)
						continue
					}
					observer.AllListeners(pwshEvent)

				}

			case <-done:
				return
			}
		}
	}()

	// Return a cancel that stops the consumer and closes the subscription handle.
	cancel = func() {
		close(done)
		evtClose(sub)
	}
	return cancel, nil
}

func firstMatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func startPowershellSubscriber() {
	EnableScriptBlockLogging()
	tailPSEventsCallback()

}
