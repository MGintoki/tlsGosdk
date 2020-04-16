package gosdk

import "time"

type Handshake struct {
	version       string
	handshakeType int //握手类型，是协商还是警告
	handShakeCode int
	sessionId     string
	sendTime      time.Time //发送时间

	//初始化HandShake时，根据handshakeCode指定了生成下面具体的消息
	clientHello       *ClientHello
	serverHello       *ServerHello
	clientKeyExchange *ClientKeyExchange
	serverFinished    *ServerFinished
	appData           *AppData
	alert             *Alert
}

type ClientHello struct {
	Handshake
	isClientEncryptRequired bool //是否需要加密
	isCertRequired          bool //是否需要服务端证书，不需要的话，说明客户端从部署指定路径获取
	cipherSuites            []int
}

type ServerHello struct {
	Handshake
	isServerEncryptRequired bool
	cipherSuite             int
	cert                    string   //服务端TLS证书
	certVerifyChain         []string //服务端TLS证书验证链
}

type ClientKeyExchange struct {
	Handshake
	symmetricKey *SymmetricKey
	MAC          string
}

type ServerFinished struct {
	Handshake
	sessionId string
	MAC       string
}

type AppData struct {
	Handshake
	data map[string]interface{}
	MAC  string
}

type Alert struct {
	Handshake
	alert string
	msg   string
}

type StateMachine struct {
	stateMachineInterface StateMachineInterface
}

//定义握手消息状态机，每个状态有一个自己的结构体，实现StateMachineInterface接口
//将处理握手消息以及状态封装到 每个状态自己的结构体实现的handleHandshake方法中
type StateMachineInterface interface {
	currentState() int
	handleHandshake(tlsConfig *TlsConfig, handshake *Handshake)
}

//客户端与服务端定义状态码
const (
	CLIENT_INIT_STATE            = 1000 //客户端已初始化tls连接
	CLIENT_SENT_CLIENT_HELLO     = 1001 //客户端已发送client hello
	CLIENT_RECEIVED_SERVER_HELLO = 1002 // 客户端已接受到server hello
	CLIENT_SENT_KEY_EXCHANGE     = 1003 //客户端已发送通信密钥
	CLIENT_NO_ENCRYPT_CONNECTION = 1004 //客户端已建立非加密连接
	CLIENT_ENCRYPTED_CONNECTION  = 1005 //客户端已建立加密连接
	CLIENT_FINISHED              = 1006 //客户端已关闭tls连接

	SERVER_INIT_STATE                  = 2000 //服务端已初始化tls连接
	SERVER_RECEIVED_CLIENT_HELLO       = 2001 //服务端已接受client hello
	SERVER_SENT_SERVER_HELLO           = 2002 //服务端已发送server hello
	SERVER_RECEIVE_CLIENT_KEY_EXCHANGE = 2003 //服务端已接受到通信密钥
	SERVER_SENT_FINISHED               = 2004 //服务端已发送开启加密通信
	SERVER_NO_ENCRYPT_CONNECTION       = 2005 //服务端已建立非加密连接
	SERVER_ENCRYPTED_CONNECTION        = 2006 //服务端已建立加密连接
	SERVER_FINISHED                    = 2007 //服务端已关闭tls连接
)

//定义handshakeCode 一个handshake或是一个alert 视作一个handshake
const (
	//每种握手消息都会有一个code，客户端或服务端接收到一个握手消息，根据code可能引起状态的转变
	CLIENT_HELLO_CODE        = 101
	CLIENT_KEY_EXCHANGE_CODE = 102
	CLIENT_CLOSE_NOTIFY_CODE = 103

	SERVER_HELLO_CODE    = 201
	SERVER_FINISHED_CODE = 202

	APP_DATA_CODE = 300

	ALERT_1 = 401

	//下面是预留的alert 的code

)
