package tetragon

func (x *ProcessConnect) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessConnect{
		ProcessConnect: x,
	}
}

func (x *ProcessListen) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessListen{
		ProcessListen: x,
	}
}

func (x *Tls) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_Tls{
		Tls: x,
	}
}

func (x *ProcessClose) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessClose{
		ProcessClose: x,
	}
}

func (x *ProcessAccept) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessAccept{
		ProcessAccept: x,
	}
}

func (x *ProcessSockStats) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessSockStats{
		ProcessSockStats: x,
	}
}

func (x *ProcessHttp) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessHttp{
		ProcessHttp: x,
	}
}

func (x *ProcessNetworkBurst) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessNetworkBurst{
		ProcessNetworkBurst: x,
	}
}

func (x *ProcessFile) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessFile{
		ProcessFile: x,
	}
}

func (x *ProcessIpError) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessIpError{
		ProcessIpError: x,
	}
}

func (x *ProcessDns) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessDns{
		ProcessDns: x,
	}
}

func (x *ProcessConnect) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessListen) SetProcess(p *Process) {
	x.Process = p
}

func (x *Tls) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessClose) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessAccept) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessSockStats) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessHttp) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessNetworkBurst) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessFile) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessIpError) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessDns) SetProcess(p *Process) {
	x.Process = p
}
