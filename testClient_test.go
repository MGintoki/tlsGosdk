package gosdk

import (
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/wumansgy/goEncrypt"
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
		SessionId:         "",
		IsClient:          true,
		HandshakeState:    &ClientInitState{},
		IsCertRequired:    true,
		IsEncryptRequired: true,
		ServerName:        "",
		State:             TLS_STATE_ACTIVING,
		CipherSuites:      []int{cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]},
		CipherSuite:       cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"],
		Time:              time.Time{},
		Timeout:           TIMEOUT,
		Randoms:           nil,
		SymmetricKey:      nil,
		Cert:              nil,
		CertChain:         nil,
		HandshakeMsgs:     hsmap,
		Logs:              nil,
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
		client.tlsConfig.HandshakeState = &ClientReceivedServerHelloState{}
		client.tlsConfig.IsEncryptRequired = true
	} else if out.ActionCode == SERVER_HELLO_CODE && out.ServerHello.IsServerEncryptRequired == false {
		client.tlsConfig.HandshakeState = &ClientNoEncryptConnectionState{}
		client.tlsConfig.IsEncryptRequired = false
	}
	fmt.Println("received server hello")
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
		PrivateKey:        []byte(PRIVATE_KEY),
		PublicKey:         []byte(PUBLIC_KEY),
		SymmetricKey:      nil,
		Cert:              []byte(CERT),
		CertChain:         nil,
		HandshakeMsgs:     hsmap,
		Logs:              nil,
	}
	server.tlsConfig = serverTlsConfig
	fmt.Println("server tls config ok")

	http.HandleFunc(LISTEN_TLS, server.handleTLS)
	http.ListenAndServe(LISTEN_URL, nil)

}
func (c *TlsServer) handleTLS(w http.ResponseWriter, r *http.Request) {
	var hs Handshake
	err := json.NewDecoder(r.Body).Decode(&hs)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("receive handshake, actionCode : ->" + strconv.Itoa(hs.ActionCode))
	fmt.Println("receive handshake info :")
	fmt.Println(hs)
	out, err := c.tlsConfig.HandshakeState.handleAction(c.tlsConfig, &hs, hs.ActionCode)
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	outByte, err := json.Marshal(out)
	w.Write(outByte)
	fmt.Println("响应成功 actionCode:" + strconv.Itoa(out.ActionCode))
	fmt.Println("响应内容：")
	fmt.Println(string(outByte))

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

func TestRSA(t *testing.T) {
	pk := []byte(privateKey2)
	puk := []byte(publicKey2)
	//plainText := []byte("testtesttesttesttesttesttest")
	plainText := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程")
	fmt.Println("plainText: " + string(plainText))
	cipherText, err := goEncrypt.RsaEncrypt(plainText, puk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("cipherText: " + string(cipherText))
	parseText, err := goEncrypt.RsaDecrypt(cipherText, pk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("parseText: " + string(parseText))
}

func TestAsy(t *testing.T) {
	pk := []byte(privateKey2)
	puk := []byte(publicKey2)
	//plainText := []byte("testtesttesttesttesttesttest")
	plainText := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程sadfdfsafsafafsa ")
	fmt.Println("plainText: " + string(plainText))
	cipherText, err := NewCipherSuiteModel(100).CipherSuiteInterface.AsymmetricKeyEncrypt(plainText, puk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("cipherText: " + string(cipherText))
	parseText, err := NewCipherSuiteModel(100).CipherSuiteInterface.AsymmetricKeyDecrypt(cipherText, pk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("parseText: " + string(parseText))

}

const (
	privateKey2 = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
MIIEpQIBAAKCAQEArDuxlkVpBB4zPoNzBh9F0OLeR8kk/8/ewryuVlj2/SM5gLaN
I8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhhLreB566m+H4TrobaRfrhe2ZQG/E2
8XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzTM1p1XlA1mrJPc7GlDKCRcUiPDn+n
Z67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8NLGMSBW8/zOxNdeC3S+8ni6HjXsj
Wft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7A0+CrDSvVGp9QPuQhdCyf6INduHp
INzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJnwIDAQABAoIBAQCOcG/WD2Fifndy
49Nk5MggkP+z7q4iwg9AjjrAPqNFhrQvtsnTJm8AtNu5bA8aO9onZBF+lpzx0R7r
Y7GWU4ZL1Igiy1ZbfCla1Tv/VBTWsS7fbQY7gDju2lCYVxH7gX7jQ6SskG900b9q
A2EFGOSyO8WFUmCCp6T90ZTmdITUYgk8iNO2bhte0ypHVef3MUrxAu6YnQUIrFIA
zP+Aq09He68ddun38uymOrIpglL5c9pQBpMLZCz866kYfHiyGbGEUyJ60rpqj6u8
1GHDIxtpM9ltwig8nygwrDmkkJw+t1QkxhIPMNbI9B7S/lzMFIZG25puWdoOg5K+
El5zRbBBAoGBAOOQtxYWKQLIDPvddbdGD3qA9J3gAOlGUO8l4V558i+aCdfwZ9NX
O744TvqlMc4P3BrqAt5naKo4tV8mxHz7bo846Y/zOAj/eO72s3Acrn0H6Pmakndn
2TIvl04m6cqoIISoorBuN9KwUImhzar1+0xxuMK2yjChGQivb4wSuC9bAoGBAMHB
CGMSaW73Cv8VBb+9RbLBOUmD7JZcqg5ENvPb50YVEVKpCre/CF1G4QZnbg85FRR3
LjG+NLJBk1dQn4EEE44iwhEGgj1jdO4lCziuJoAWTsFwHpTiJDhdW78ZNsgHejC+
tNrQB0y+Uah5c06p4VJu/kSbr/MoFzenqiva3wYNAoGBAIbZ1uTrtNnFGoyWK4+z
oLCDgnGbsG6MEKHm3KpTsUSsD3E7MQt4Ahsy2vqEsgLeOxxn19NbjBZzDGeaXY2C
oX2VyDJZerc6TLuuzZ5+IJhO+6wOAQVpMLggo5TYUmqZPsvd8qqCZeogOVmV3H6W
zZf7O/WGxEIU9PTEoWFsJmFJAoGAFpD1+hv93ae2Rylapw9TW9N3aaGM36JhSBIX
2GUnVZlEkD0R+36rabnEoatQPUOnud97qN1/Y7eRgpzoRu2DnY1czwDUEHRR/R6h
ZPObllWCzLLTTQHduBbfha1ZHQkJ6T188PNDtmOAPUAP9vyAOsqkoLcFUiu8MIY9
oqf2S80CgYEAppFtMX0bCbBZJwMWY4oskk1IC4y99ogEL0itMGOyxcaVffKRJtkD
v3jylXAUVxu55chy0rbPe4jtgDx/E5k1ZkTNTytOoB1VGblmuGtKWYQe3ITS6V0x
ss2ih/aaR47pzNvK5Z6G/AKtkAy6EubKKGBgMfg+9iiX/IbweFvvb7Y=
-----END  WUMAN RSA PRIVATE KEY -----`
	publicKey2 = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
)
