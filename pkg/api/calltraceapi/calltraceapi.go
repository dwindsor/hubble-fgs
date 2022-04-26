package calltraceapi

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}
