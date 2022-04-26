package calltraceapi

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}
