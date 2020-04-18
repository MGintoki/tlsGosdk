package gosdk

import (
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func HelloServer2(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Inside HelloServer handler")
	fmt.Fprintf(w, "Hello,"+req.URL.Path[1:])
}

func TestHelloServer(t *testing.T) {

	http.HandleFunc("/", HelloServer2)
	err := http.ListenAndServe("localhost:8081", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err.Error())
	}

}

func TestHelloClient(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8081/hello")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

}

func TestClientStartTLS(t *testing.T) {
	//初始化client
	client := TlsClient{
		clientInfo:  "testClient",
		serverInfo:  "testServer",
		requestPath: "http://127.0.0.1:8081",
		tlsConfig:   nil,
	}
	//初始化client的tlsConfig
	hsmap := map[int]Handshake{}
	clientTlsConfig := &TlsConfig{
		SessionId:      "",
		IsClient:       true,
		HandshakeState: &ClientInitState{},
		IsCertRequired: true,
		ServerName:     "",
		State:          TLS_STATE_ACTIVING,
		CipherSuites:   []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		CipherSuite:    cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		Time:           time.Time{},
		Timeout:        TIMEOUT,
		Randoms:        nil,
		Keypair:        nil,
		SymmetricKey:   nil,
		Cert:           "",
		CertChain:      []string{},
		HandshakeMsgs:  hsmap,
		Logs:           nil,
	}
	client.tlsConfig = clientTlsConfig
	fmt.Println("client tls config ok")
	fmt.Println("handshake state -> client_init")
	//发送client hello
	out, err := client.tlsConfig.HandshakeState.handleAction(clientTlsConfig, nil, CLIENT_HELLO_CODE)
	if err != nil {
		log.Fatal(err)
	}
	//如果server hello 中需要加密，client 进入 已接收server hello 状态
	//如果不需要加密，进入非加密连接状态
	if out.ActionCode == SERVER_HELLO_CODE && out.ServerHello.IsServerEncryptRequired {
		client.tlsConfig.HandshakeState = &ClientReceivedServerHello{}
		client.tlsConfig.IsEncryptRequired = true
	} else if out.ActionCode == SERVER_HELLO_CODE && out.ServerHello.IsServerEncryptRequired == false {
		client.tlsConfig.HandshakeState = &ClientNoEncryptConnection{}
		client.tlsConfig.IsEncryptRequired = false
	}
	fmt.Println("send client hello success")
	out, err = client.tlsConfig.HandshakeState.handleAction(client.tlsConfig, out, out.ActionCode)
	if err != nil {
		log.Fatal(err)
	}

}

func TestServerStartTLS(t *testing.T) {
	server := &TlsServer{
		serverInfo: "test server",
		listenPath: "localhost:8081",
		tlsConfig:  nil,
	}
	hsmap := map[int]Handshake{}
	serverTlsConfig := &TlsConfig{
		SessionId:         "",
		IsClient:          false,
		HandshakeState:    &ServerInitState{},
		IsEncryptRequired: true,
		IsCertRequired:    false,
		ServerName:        "testServerName",
		State:             TLS_STATE_ACTIVING,
		CipherSuites:      []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		CipherSuite:       cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		Time:              time.Time{},
		Timeout:           TIMEOUT,
		Randoms:           nil,
		Keypair: &keypair{
			PrivateKey:  PRIVATE_KEY,
			PublicKey:   PUBLIC_KEY,
			KeypairType: "rsa",
		},
		SymmetricKey:  &SymmetricKey{},
		Cert:          CERT,
		CertChain:     nil,
		HandshakeMsgs: hsmap,
		Logs:          nil,
	}
	server.tlsConfig = serverTlsConfig
	fmt.Println("server tls config ok")

	http.HandleFunc(LISTEN_TLS, server.handleTLS)
	http.ListenAndServe(LISTEN_URL, nil)

}
func (c *TlsServer) handleTLS(w http.ResponseWriter, r *http.Request) {
	fmt.Println("receive handshake")
	var hs Handshake
	err := json.NewDecoder(r.Body).Decode(&hs)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("receive handshake")
	out, err := c.tlsConfig.HandshakeState.handleAction(c.tlsConfig, &hs, hs.ActionCode)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	outByte, err := json.Marshal(out)
	w.Write(outByte)
	c.tlsConfig.HandshakeState = &ServerSendServerHelloState{}
	fmt.Println("响应成功" + strconv.Itoa(out.ActionCode))

	//w.Header().Set("Content-Type", "application/json; charset=utf-8")
	//ch := &ClientHello{
	//	IsClientEncryptRequired: true,
	//	IsCertRequired:          false,
	//}
	//hs := &Handshake{
	//	Version:       "version",
	//	HandshakeType: 1,
	//	SendTime:      time.Time{},
	//}
	//hs.ClientHello = ch
	//hsMarshal, err := json.Marshal(hs)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//w.Write(hsMarshal)
}
