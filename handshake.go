package gosdk

import "time"

type handshake struct {
	version       string
	handshakeType string    //握手类型，根据该类型判断下面哪个指针已赋值
	sendTime      time.Time //发送时间

	//clientHello       *clientHello
	//serverHello       *serverHello
	//clientKeyExchange *clientKeyExchange
	//serverFinished    *serverFinished
}

type symmetricKey struct {
}
type clientHello struct {
	handshake
	isClientEncryptRequired bool //是否需要加密
	sessionId               string
	isCertRequired          bool //是否需要服务端证书，不需要的话，说明客户端从部署指定路径获取
	cipherSuites            []*cipherSuite
}

type serverHello struct {
	handshake
	isServerEncryptRequired bool
	sessionId               string
	cipher                  *cipherSuite
	cert                    string   //服务端TLS证书
	certVerifyChain         []string //服务端TLS证书验证链
}

type clientKeyExchange struct {
	handshake
	sessionId    string
	symmetricKey *symmetricKey
	MAC          string
}

type serverFinished struct {
	handshake
	sessionId string
	MAC       string
}
