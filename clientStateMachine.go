package gosdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/errno"
	"log"
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
		tlsConfig.HandshakeState = &ClientSentClientHello{}
		tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE] = *clientHelloHandshake
		return out, err

	default:
		return out, err

	}
	return
}

type ClientSentClientHello struct {
}

func (c *ClientSentClientHello) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO_STATE
}

func (c *ClientSentClientHello) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch handshake.ActionCode {
	case SERVER_HELLO_CODE:

	}
	return
}

type ClientReceivedServerHello struct {
}

func (c *ClientReceivedServerHello) currentState() int {
	return CLIENT_RECEIVED_SERVER_HELLO_STATE
}

func (c *ClientReceivedServerHello) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SERVER_HELLO_CODE:
		if !VerifyCert(handshake.ServerHello.Cert, handshake.ServerHello.CertVerifyChain, handshake.ServerHello.PublicKey) {
			return out, errno.CERT_VERIFY_ERROR
		}
		tlsConfig.CipherSuite = handshake.ServerHello.CipherSuite
		//如果客户端不能直接获取服务端的证书和公钥，使用server hello 里的证书
		if tlsConfig.IsCertRequired {
			tlsConfig.Cert = handshake.ServerHello.Cert
			tlsConfig.CertChain = handshake.ServerHello.CertVerifyChain
		}
		symmetricKey := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateSymmetricKey(tlsConfig.Randoms)
		tlsConfig.SymmetricKey = symmetricKey
		clientKeyExchange := ClientKeyExchange{
			SymmetricKey: *symmetricKey,
			MAC:          "",
		}
		clientKeyExchangeHandshake := &Handshake{
			Version:           "",
			HandshakeType:     0,
			ActionCode:        CLIENT_KEY_EXCHANGE_CODE,
			SessionId:         symmetricKey.SessionId,
			SendTime:          time.Time{},
			ClientKeyExchange: &clientKeyExchange,
		}
		//留待生成MAC摘要，填入clientKeyExchange中

		fmt.Println("generate client key exchange")
		out, err := SendHandshake(clientKeyExchangeHandshake)
		if err != nil {
			log.Fatal(out)
		}
		tlsConfig.HandshakeState = &ClientSentKeyExchange{}
		return out, err
	}
	return
}

type ClientSentKeyExchange struct {
}

func (c *ClientSentKeyExchange) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO_STATE
}

func (c *ClientSentKeyExchange) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ClientNoEncryptConnection struct {
}

func (c *ClientNoEncryptConnection) currentState() int {
	panic("implement me")
}

func (c *ClientNoEncryptConnection) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}
