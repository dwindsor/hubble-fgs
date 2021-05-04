package api

type MsgGenericKprobeArgString struct {
	Index uint64
	Value string
}

type MsgGenericKprobeArgBytes struct {
	Index uint64
	Value []byte
}

type MsgGenericKprobeArgInt struct {
	Index uint64
	Value int32
}

type MsgGenericKprobeArgSize struct {
	Index uint64
	Value uint64
}

type MsgGenericKprobeSkb struct {
	Hash     uint32
	Len      uint32
	Priority uint32
	Mark     uint32
}

type MsgGenericKprobeArgSkb struct {
	Index    uint64
	Hash     uint32
	Len      uint32
	Priority uint32
	Mark     uint32
}

type MsgGenericKprobeArg interface{}

type MsgGenericKprobeUnix struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         uint64
	FuncName   string
	Args       []MsgGenericKprobeArg
}
