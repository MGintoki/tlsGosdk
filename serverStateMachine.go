package gosdk

import (
	"encoding/json"
	"fmt"
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
					PublicKey:               tlsConfig.PublicKey,
					CipherSuite:             0,
					Cert:                    nil,
					CertVerifyChain:         nil,
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
					SessionId:     CreateSessionId(),
					SendTime:      time.Time{},
					ServerHello:   serverHello,
				}
				tlsConfig.SessionId = serverHelloHandshake.SessionId
				//将server hello 放入handshake msgs 中，用以生成MAC
				tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE] = *handshake
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
		symmetricKeyByte := handshake.ClientKeyExchange.SymmetricKey
		//因为接收到的SymmetricKey是采用公钥加密的，所以要先用私钥解密
		symmetricKeyParse, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.AsymmetricKeyDecrypt(symmetricKeyByte, tlsConfig.PrivateKey)
		if err != nil {
			return out, errno.SYMMETRIC_KEY_DECRYPT_ERROR.Add(err.Error())
		}
		var symmetricKey []byte
		err = json.Unmarshal(symmetricKeyParse, &symmetricKey)
		if err != nil {
			return out, errno.JSON_ERROR.Add("Server SymmetricKey Unmarshal error")
		}
		//将协商好的symmetricKey放入服务端tlsConfig中
		tlsConfig.SymmetricKey = symmetricKey
		//将对称密钥加密的MAC解密
		clientEncryptedMAC := handshake.ClientKeyExchange.MAC
		clientMAC, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(clientEncryptedMAC, tlsConfig.SymmetricKey)
		if err != nil {
			return out, errno.SYMMETRIC_KEY_DECRYPT_ERROR.Add(err.Error())
		}
		//将client key exchange 保存到server tlsConfig中

		tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE] = *handshake
		serverMAC, err := CreateNegotiateMAC(tlsConfig)
		if err != nil {
			return out, errno.CREATE_MAC_ERROR.Add("Server Create MAC Error")
		}
		if string(clientMAC) != string(serverMAC) {
			return out, errno.MAC_VERIFY_ERROR.Add("Server Verify MAC Error" + err.Error())
		}
		//生成Server Finished 开启加密通信
		serverFinished := &ServerFinished{
			SessionId: tlsConfig.SessionId,
			MAC:       nil,
		}
		//将服务器端的三次握手消息用通信密钥加密
		encryptedServerMAC, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(serverMAC, tlsConfig.SymmetricKey)
		if err != nil {
			return out, errno.SYMMETRIC_KEY_ENCRYPT_ERROR.Add("Server Encrypt MAC Error " + err.Error())
		}
		serverFinished.MAC = encryptedServerMAC
		serverFinishedHandshake := &Handshake{
			Version:        "",
			HandshakeType:  0,
			ActionCode:     SERVER_FINISHED_CODE,
			SessionId:      tlsConfig.SessionId,
			SendTime:       time.Time{},
			ServerFinished: serverFinished,
		}
		fmt.Println("create server finished")
		return serverFinishedHandshake, err

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
