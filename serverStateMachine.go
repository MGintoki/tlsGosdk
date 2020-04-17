package gosdk

type ServerInitState struct {
}

func (c *ServerInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ServerInitState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ServerReceivedClientHello struct {
}

func (c *ServerReceivedClientHello) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ServerReceivedClientHello) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}
