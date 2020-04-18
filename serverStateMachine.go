package gosdk

import (
	"github.com/pretty66/gosdk/cipherSuites"
	"time"
)

type ServerInitState struct {
}

func (c *ServerInitState) currentState() int {
	return SERVER_INIT_STATE
}

func (c *ServerInitState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case CLIENT_HELLO_CODE:
		//如果client hello的session id不为空，尝试复用session id 对应的配置
		//否则 需要重新协商密钥
		if handshake.SessionId != "" {

		} else {
			//如果用户client hello 中需要开启加密，或是服务器配置需要加密，则进行加密处理
			if handshake.ClientHello.IsClientEncryptRequired || tlsConfig.IsEncryptRequired {
				serverHello := &ServerHello{
					IsServerEncryptRequired: true,
					PublicKey:               tlsConfig.Keypair.PublicKey,
					CipherSuite:             0,
				}
				//根据客户端加密套件表和服务端加密套件表，协商合适的加密套件
				cipherSuite := negotiateCipherSuite(handshake.ClientHello.CipherSuites, tlsConfig.CipherSuites)
				serverHello.CipherSuite = cipherSuite
				if handshake.ClientHello.IsCertRequired {
					serverHello.Cert = tlsConfig.Cert
					serverHello.CertVerifyChain = tlsConfig.CertChain
				}
				serverHelloHandshake := &Handshake{
					Version:       "",
					HandshakeType: 0,
					ActionCode:    SERVER_HELLO_CODE,
					SessionId:     "",
					SendTime:      time.Time{},
					ServerHello:   serverHello,
				}
				return serverHelloHandshake, err
				//不需要开启加密通信
			} else {

			}
		}
	}
	return
}

func negotiateCipherSuite(clientCipherSuites, serverCipherSuites []int) int {
	return cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]
}

type ServerReceivedClientHello struct {
}

func (c *ServerReceivedClientHello) currentState() int {
	return SERVER_RECEIVED_CLIENT_HELLO_STATE
}

func (c *ServerReceivedClientHello) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ServerSendServerHelloState struct {
}

func (s ServerSendServerHelloState) currentState() int {
	return SERVER_SENT_SERVER_HELLO_STATE
}

func (s ServerSendServerHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case CLIENT_KEY_EXCHANGE_CODE:
		tlsConfig.SessionId = handshake.SessionId

	}
}

type ServerReceivedClientKeyExchange struct {
}

func (s ServerReceivedClientKeyExchange) currentState() int {
	return SERVER_RECEIVE_CLIENT_KEY_EXCHANGE_STATE
}

func (s ServerReceivedClientKeyExchange) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}
