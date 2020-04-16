package gosdk

type ServerInitState struct {
}

func (c *ServerInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ServerInitState) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}

type ServerReceivedClientHello struct {
}

func (c *ServerReceivedClientHello) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ServerReceivedClientHello) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}
