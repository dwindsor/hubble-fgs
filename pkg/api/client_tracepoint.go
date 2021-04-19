package api

type MsgGenericTracepointArg interface{}

type MsgGenericTracepointUnix struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         int64
	Subsys     string
	Event      string
	Args       []MsgGenericTracepointArg
}

type MsgGenericTracepoint struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         int64
	ThreadId   uint64
}
