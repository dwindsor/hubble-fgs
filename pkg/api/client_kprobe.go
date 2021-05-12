package api

type MsgGenericKprobeArgString struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgString) GetIndex() uint64 {
	return m.Index
}

type MsgGenericKprobeArgBytes struct {
	Index uint64
	Value []byte
}

func (m MsgGenericKprobeArgBytes) GetIndex() uint64 {
	return m.Index
}

type MsgGenericKprobeArgInt struct {
	Index uint64
	Value int32
}

func (m MsgGenericKprobeArgInt) GetIndex() uint64 {
	return m.Index
}

type MsgGenericKprobeArgSize struct {
	Index uint64
	Value uint64
}

func (m MsgGenericKprobeArgSize) GetIndex() uint64 {
	return m.Index
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

func (m MsgGenericKprobeArgSkb) GetIndex() uint64 {
	return m.Index
}

type MsgGenericKprobeArg interface {
	GetIndex() uint64
}

type MsgGenericKprobeUnix struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         uint64
	FuncName   string
	Args       []MsgGenericKprobeArg
}
