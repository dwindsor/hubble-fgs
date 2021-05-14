package api

const (
	sizeofArgsFilter = 80
	// 5 arguments + 1 return argument
	MaxArgsSupported = 6
	ReturnArgIndex   = MaxArgsSupported - 1
)

type MsgGenericKprobeArgString struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgString) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgString) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgBytes struct {
	Index uint64
	Value []byte
}

func (m MsgGenericKprobeArgBytes) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgBytes) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgInt struct {
	Index uint64
	Value int32
}

func (m MsgGenericKprobeArgInt) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgInt) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgSize struct {
	Index uint64
	Value uint64
}

func (m MsgGenericKprobeArgSize) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSize) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
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

func (m MsgGenericKprobeArgSkb) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArg interface {
	GetIndex() uint64
	IsReturnArg() bool
}

type MsgGenericKprobeUnix struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         uint64
	FuncName   string
	Args       []MsgGenericKprobeArg
}
