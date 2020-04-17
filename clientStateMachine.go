package gosdk

func SendHandshake(handshake *Handshake) {

}

type ClientInitState struct {
}

func (c *ClientInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ClientInitState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SEND_CLIENT_HELLO_CODE:

	case 0:

	default:
		return out, err

	}
	return out, err
}

type ClientSentClientHello struct {
}

func (c *ClientSentClientHello) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO
}

func (c *ClientSentClientHello) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch handshake.actionCode {
	case SERVER_HELLO_CODE:

	}
}

type ClientReceivedServerHello struct {
}

func (c *ClientReceivedServerHello) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ClientSentKeyExchange struct {
}

func (c *ClientSentKeyExchange) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}
