package gosdk

import (
	"encoding/json"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/pretty66/gosdk/errno"
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
				//将server hello 放入handshake msgs 中，用以生成MAC
				tlsConfig.HandshakeMsgs[SERVER_HELLO_CODE] = *serverHelloHandshake
				tlsConfig.HandshakeState = &ServerSentServerHelloState{}
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

type ServerReceivedClientHelloState struct {
}

func (c *ServerReceivedClientHelloState) currentState() int {
	return SERVER_RECEIVED_CLIENT_HELLO_STATE
}

func (c *ServerReceivedClientHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ServerSentServerHelloState struct {
}

func (s ServerSentServerHelloState) currentState() int {
	return SERVER_SENT_SERVER_HELLO_STATE
}

func (s ServerSentServerHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case CLIENT_KEY_EXCHANGE_CODE:
		tlsConfig.SessionId = handshake.SessionId
		symmetricKeyStr := handshake.ClientKeyExchange.SymmetricKey
		symmetricKeyByte := []byte(symmetricKeyStr)
		symmetricKey := &SymmetricKey{}
		err := json.Unmarshal(symmetricKeyByte, symmetricKey)
		if err != nil {
			return out, errno.JSON_ERROR.Add("SymmetricKey Unmarshal error")
		}
		tlsConfig.SymmetricKey = symmetricKey
		clientMAC := handshake.ClientKeyExchange.MAC
		//将client key exchange 保存到server tlsConfig中
		//client CreateMAC时，client key exchange的MAC是空的，所以服务端这里生成时也要置MAC为空
		tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE] = *handshake
		tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange.MAC = ""
		serverMAC, err := CreateNegotiateMAC(tlsConfig)
		if clientMAC != serverMAC {
			return out, errno.MAC_VERIFY_ERROR.Add("Server Verify MAC Error" + err.Error())
		}
		if err != nil {
			return out, errno.CREATE_MAC_ERROR.Add("Server Create MAC Error")
		}

	}
	return
}

type ServerReceivedClientKeyExchangeState struct {
}

func (s ServerReceivedClientKeyExchangeState) currentState() int {
	return SERVER_RECEIVE_CLIENT_KEY_EXCHANGE_STATE
}

func (s ServerReceivedClientKeyExchangeState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}
