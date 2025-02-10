# EXPERIMENTAL: Tetragon Aggregator

Tetragon Aggregator (formerly known as Squash) is an experimental component of
Tetragon Enterprise. It exposes an HTTP endpoint to receive ApplicationModel
JSON from Tetragon pods and aggregates them into a single ApplicationModel to
provide a cluster-wide view of the applications.

## Known Limitations

- It only supports plaintext HTTP, not HTTPS.
- It does not aggregate bytes_sent / bytes_received fields correctly.
- It does not garbage collect processes that terminated, so ApplicationModel
  could grow indefinitely.