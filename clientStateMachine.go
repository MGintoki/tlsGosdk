package gosdk

import (
	"log"
)

type ClientInitState struct {
}

func (c *ClientInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ClientInitState) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	log.Println("clientInitState")
}

type ClientSentClientHello struct {
}

func (c *ClientSentClientHello) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO
}

func (c *ClientSentClientHello) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	switch handshake.handShakeCode {
	case SERVER_HELLO_CODE:

	}
}

type ClientReceivedServerHello struct {
}

func (c *ClientReceivedServerHello) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}

type ClientSentKeyExchange struct {
}

func (c *ClientSentKeyExchange) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}
