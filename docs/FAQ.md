# Tetragon FAQ

## Alerts

### Can I use CEL to filter all events based on process information?

You can use a `filter` expression over all the event types that are you are interested in.
For example:
```
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: >
    [process_exec, process_exit, process_kprobe, process_tracepoint, process_connect].filter(
      ev, ev.process.binary == "/usr/bin/dash"
    ).size() > 0
  message: test
  severity: info
  tags: []
```
