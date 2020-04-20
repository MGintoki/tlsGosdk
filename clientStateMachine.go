package gosdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/errno"
	"net/http"
	"time"
)

func SendHandshake(handshake *Handshake) (out *Handshake, err error) {
	client := http.Client{}
	url := GetHSRequestRoute()
	hsByte, err := json.Marshal(handshake)
	if err != nil {
		return out, err
	}
	request, err := http.NewRequest("POST", url, bytes.NewReader(hsByte))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return out, err
	}
	response, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&out)
	return out, err

}

type ClientInitState struct {
}

func (c *ClientInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ClientInitState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case CLIENT_HELLO_CODE:
		clientHello := &ClientHello{
			IsClientEncryptRequired: tlsConfig.IsEncryptRequired,
			IsCertRequired:          tlsConfig.IsCertRequired,
			CipherSuites:            tlsConfig.CipherSuites,
		}
		clientHelloHandshake := &Handshake{
			Version:       "",
			HandshakeType: 0,
			ActionCode:    CLIENT_HELLO_CODE,
			SessionId:     tlsConfig.SessionId,
			SendTime:      time.Time{},
			ClientHello:   clientHello,
		}
		fmt.Println("client hello handshake init ")
		out, err = SendHandshake(clientHelloHandshake)
		fmt.Println("client hello sent")
		if err != nil {
			return out, err
		}
		tlsConfig.HandshakeState = &ClientSentClientHelloState{}
		tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE] = *clientHelloHandshake
		return out, err

	default:
		return out, err

	}
	return
}

type ClientSentClientHelloState struct {
}

func (c *ClientSentClientHelloState) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO_STATE
}

func (c *ClientSentClientHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch handshake.ActionCode {
	case SERVER_HELLO_CODE:

	}
	return
}

type ClientReceivedServerHelloState struct {
}

func (c *ClientReceivedServerHelloState) currentState() int {
	return CLIENT_RECEIVED_SERVER_HELLO_STATE
}

func (c *ClientReceivedServerHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SERVER_HELLO_CODE:
		if !VerifyCert(handshake.ServerHello.Cert, handshake.ServerHello.CertVerifyChain, handshake.ServerHello.PublicKey) {
			return out, errno.CERT_VERIFY_ERROR
		}
		tlsConfig.CipherSuite = handshake.ServerHello.CipherSuite
		//如果客户端不能直接获取服务端的证书和公钥，使用server hello 里的证书以及公钥

		if tlsConfig.IsCertRequired {
			tlsConfig.Cert = handshake.ServerHello.Cert
			tlsConfig.CertChain = handshake.ServerHello.CertVerifyChain
			tlsConfig.PublicKey = handshake.ServerHello.PublicKey
		}
		tlsConfig.SessionId = handshake.SessionId
		//将来会有从本地获取部署指定路径的证书以及公钥
		symmetricKey := CreateSymmetricKey(handshake.ServerHello.CipherSuite, tlsConfig.Randoms)
		tlsConfig.SymmetricKey = symmetricKey
		//使用公钥加密通信密钥
		symmetricKeyByte, err := json.Marshal(tlsConfig.SymmetricKey)
		////if err != nil {
		////	return out, errno.JSON_ERROR.Add("SymmetricKey Marshal error")
		////}
		encryptedSymmetricKey, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.AsymmetricKeyEncrypt(symmetricKeyByte, tlsConfig.PublicKey)
		if err != nil {
			return out, errno.ASYMMETRIC_ENCRYPT_ERROR.Add(err.Error())
		}
		//生成handshake
		clientKeyExchange := ClientKeyExchange{
			//SymmetricKey: encryptedSymmetricKey,
			SymmetricKey: encryptedSymmetricKey,
			MAC:          nil,
		}
		clientKeyExchangeHandshake := &Handshake{
			Version:           "",
			HandshakeType:     0,
			ActionCode:        CLIENT_KEY_EXCHANGE_CODE,
			SessionId:         tlsConfig.SessionId,
			SendTime:          time.Time{},
			ClientKeyExchange: &clientKeyExchange,
		}
		tlsConfig.HandshakeMsgs[SERVER_HELLO_CODE] = *handshake
		tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE] = *clientKeyExchangeHandshake
		//生成MAC摘要，填入clientKeyExchange中
		MAC, err := CreateNegotiateMAC(tlsConfig)
		MACEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(MAC, tlsConfig.SymmetricKey)
		if err != nil {
			return out, errno.CREATE_MAC_ERROR.Add("Client Create MAC Error")
		}
		clientKeyExchangeHandshake.ClientKeyExchange.MAC = MACEncrypted
		fmt.Println("generate client key exchange")
		out, err := SendHandshake(clientKeyExchangeHandshake)
		fmt.Println("sent client key exchange")
		tlsConfig.HandshakeState = &ClientSentKeyExchangeState{}
		if err != nil {
			return out, err
		}
		fmt.Println("received server Finished")
		tlsConfig.HandshakeState = &ClientReceivedServerHelloState{}
		return out, err
	}
	return
}

type ClientSentKeyExchangeState struct {
}

func (c *ClientSentKeyExchangeState) currentState() int {
	return CLIENT_SENT_KEY_EXCHANGE_STATE
}

func (c *ClientSentKeyExchangeState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ClientNoEncryptConnectionState struct {
}

func (c *ClientNoEncryptConnectionState) currentState() int {
	return CLIENT_NO_ENCRYPT_CONNECTION_STATE
}

func (c *ClientNoEncryptConnectionState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ClientEncryptedConnectionState struct {
}

func (c *ClientEncryptedConnectionState) currentState() int {
	return CLIENT_ENCRYPTED_CONNECTION_STATE
}

func (c *ClientEncryptedConnectionState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {

	}
	return
}
