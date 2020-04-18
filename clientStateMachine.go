package gosdk

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func (c *ClientReceivedServerHello) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	panic("implement me")
}

type ClientSentKeyExchange struct {
}

func (c *ClientSentKeyExchange) handleHandshake(tlsConfig *TlsConfig, handshake *Handshake) {
	panic("implement me")
}
