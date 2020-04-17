package gosdk

import (
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"io/ioutil"
	"log"
	"net/http"
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
		Time:           nil,
		Timeout:        nil,
		Randoms:        nil,
		Keypair:        nil,
		SymmetricKey:   nil,
		Cert:           nil,
		CertChain:      nil,
		HandshakeMsgs:  hsmap,
		Logs:           nil,
	}

	client.tlsConfig = clientTlsConfig
	fmt.Println("client tls config ok")
	fmt.Println("handshake state -> client_init")
	//生成client hello
	clientHello := &ClientHello{
		IsClientEncryptRequired: true,
		IsCertRequired:          true,
		CipherSuites:            []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
	}
	chHandshake := &Handshake{
		Version:           "",
		HandshakeType:     0,
		ActionCode:        CLIENT_HELLO_CODE,
		SessionId:         "",
		SendTime:          time.Time{},
		ClientHello:       clientHello,
		ServerHello:       nil,
		ClientKeyExchange: nil,
		ServerFinished:    nil,
		AppData:           nil,
		Alert:             nil,
	}
	//发送client hello
	client.tlsConfig.HandshakeState.handleAction(clientTlsConfig, chHandshake, SEND_CLIENT_HELLO_CODE)
	fmt.Println("send client hello")
}

func TestServerStartTLS(t *testing.T) {
	server := &TlsServer{
		serverInfo: "test server",
		listenPath: "localhost:8081",
		tlsConfig:  nil,
	}
	hsmap := map[int]Handshake{}
	serverTlsConfig := &TlsConfig{
		SessionId:      "",
		IsClient:       false,
		HandshakeState: &ServerInitState{},
		IsCertRequired: false,
		ServerName:     "testServerName",
		State:          TLS_STATE_ACTIVING,
		CipherSuites:   []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		CipherSuite:    cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		Time:           nil,
		Timeout:        nil,
		Randoms:        nil,
		Keypair: keypair{
			PrivateKey:  PRIVATE_KEY,
			PublicKey:   PUBLIC_KEY,
			KeypairType: "rsa",
		},
		SymmetricKey:  SymmetricKey{},
		Cert:          CERT,
		CertChain:     nil,
		HandshakeMsgs: hsmap,
		Logs:          nil,
	}
	server.tlsConfig = serverTlsConfig
	fmt.Println("server tls config ok")
	//监听请求
	for server.tlsConfig.HandshakeState.currentState() == SERVER_INIT_STATE {
		//测试的client hello
		clientHello := &ClientHello{
			IsClientEncryptRequired: true,
			IsCertRequired:          true,
			CipherSuites:            []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		}
		fmt.Println(clientHello)
		server.tlsConfig.HandshakeState.handleAction(server.tlsConfig, nil, CLIENT_HELLO_CODE)
	}
}
