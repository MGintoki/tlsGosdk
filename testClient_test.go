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
		sessionId:      "",
		isClient:       true,
		handshakeState: &ClientInitState{},
		isCertRequired: true,
		serverName:     "",
		state:          TLS_STATE_ACTIVING,
		cipherSuites:   []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		cipherSuite:    cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		time:           nil,
		timeout:        nil,
		randoms:        nil,
		keypair:        nil,
		symmetricKey:   nil,
		cert:           nil,
		certChain:      nil,
		handshakeMsgs:  hsmap,
		logs:           nil,
	}

	client.tlsConfig = clientTlsConfig
	fmt.Println("client tls config ok")
	fmt.Println("handshake state -> client_init")
	//生成client hello
	clientHello := &ClientHello{
		Handshake: Handshake{
			actionCode: CLIENT_HELLO_CODE,
		},
		isClientEncryptRequired: true,
		isCertRequired:          true,
		cipherSuites:            []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
	}
	chHandshake := &Handshake{
		version:           "",
		handshakeType:     0,
		actionCode:        CLIENT_HELLO_CODE,
		sessionId:         "",
		sendTime:          time.Time{},
		clientHello:       clientHello,
		serverHello:       nil,
		clientKeyExchange: nil,
		serverFinished:    nil,
		appData:           nil,
		alert:             nil,
	}
	//发送client hello
	client.tlsConfig.handshakeState.handleAction(clientTlsConfig, chHandshake, SEND_CLIENT_HELLO_CODE)
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
		sessionId:      "",
		isClient:       false,
		handshakeState: &ServerInitState{},
		isCertRequired: false,
		serverName:     "testServerName",
		state:          TLS_STATE_ACTIVING,
		cipherSuites:   []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		cipherSuite:    cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		time:           nil,
		timeout:        nil,
		randoms:        nil,
		keypair: keypair{
			privateKey:  PRIVATE_KEY,
			publicKey:   PUBLIC_KEY,
			keypairType: "rsa",
		},
		symmetricKey:  SymmetricKey{},
		cert:          CERT,
		certChain:     nil,
		handshakeMsgs: hsmap,
		logs:          nil,
	}
	server.tlsConfig = serverTlsConfig
	fmt.Println("server tls config ok")
	//监听请求
	for server.tlsConfig.handshakeState.currentState() == SERVER_INIT_STATE {
		//测试的client hello
		clientHello := &ClientHello{
			Handshake: Handshake{
				actionCode: CLIENT_HELLO_CODE,
			},
			isClientEncryptRequired: true,
			isCertRequired:          true,
			cipherSuites:            []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		}
		fmt.Println(clientHello)
		server.tlsConfig.handshakeState.handleAction(server.tlsConfig, nil, CLIENT_HELLO_CODE)
	}
}
