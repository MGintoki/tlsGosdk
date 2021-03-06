package gosdk

import (
	"time"
)

type Handshake struct {
	Version       string    `json:"version"`
	HandshakeType int       `json:"handshakeType"` //握手类型，是协商还是警告
	ActionCode    int       `json:"actionCode"`
	SessionId     string    `json:"sessionId"`
	SendTime      time.Time `json:"sendTime"` //发送时间

	//初始化HandShake时，根据handshakeCode指定了生成下面具体的消息
	ClientHello       *ClientHello       `json:"clientHello"`
	ServerHello       *ServerHello       `json:"serverHello"`
	ClientKeyExchange *ClientKeyExchange `json:"clientKeyExchange"`
	ServerFinished    *ServerFinished    `json:"serverFinished"`
	AppData           *AppData           `json:"appData"`
	ClientCloseNotify *ClientCloseNotify `json:"clientCloseNotify"`
	Alert             *Alert             `json:"alert"`
}

type ClientHello struct {
	IsClientEncryptRequired bool   `json:"isClientEncryptRequired"` //是否需要加密
	IsCertRequired          bool   `json:"isCertRequired"`          //是否需要服务端证书，不需要的话，说明客户端从部署指定路径获取
	CipherSuites            []int  `json:"cipherSuites"`
	Random                  string `json:"random"`
}

type ServerHello struct {
	IsServerEncryptRequired bool   `json:"isServerEncryptRequired"`
	CipherSuite             int    `json:"cipherSuite"`
	PublicKey               []byte `json:"publicKey"`
	Cert                    []byte `json:"cert"`            //服务端TLS证书
	CertVerifyChain         []byte `json:"certVerifyChain"` //服务端TLS证书验证链
	Random                  string `json:"random"`
}

type ClientKeyExchange struct {
	SymmetricKey []byte `json:"symmetricKey"`
	Random       string `json:"random"`
	MAC          string `json:"MAC"`
}

type ServerFinished struct {
	SessionId string `json:"sessionId"`
	MAC       string `json:"MAC"`
}

type AppData struct {
	Data string `json:"data"`
	MAC  string `json:"MAC"`
}

type ClientCloseNotify struct {
}

type Alert struct {
	Alert string `json:"alert"`
	Msg   string `json:"msg"`
}

type StateMachine struct {
	StateMachineInterface StateMachineInterface `json:"stateMachineInterface"`
}

//定义握手消息状态机，每个状态有一个自己的结构体，实现StateMachineInterface接口
//将处理握手消息以及状态封装到 每个状态自己的结构体实现的handleHandshake方法中
type StateMachineInterface interface {
	currentState() int
	handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error)
}

//客户端与服务端定义状态码
const (
	CLIENT_INIT_STATE                     = 1000 //客户端已初始化tls连接
	CLIENT_SENT_CLIENT_HELLO_STATE        = 1001 //客户端已发送client hello
	CLIENT_RECEIVED_SERVER_HELLO_STATE    = 1002 // 客户端已接受到server hello
	CLIENT_SENT_KEY_EXCHANGE_STATE        = 1003 //客户端已发送通信密钥
	CLIENT_RECEIVED_SERVER_FINISHED_STATE = 1004 //客户度啊接收到server finished
	CLIENT_NO_ENCRYPT_CONNECTION_STATE    = 1005 //客户端已建立非加密连接
	CLIENT_ENCRYPTED_CONNECTION_STATE     = 1006 //客户端已建立加密连接
	CLIENT_CLOSED_STATE                   = 1007 //客户端已关闭tls连接

	SERVER_INIT_STATE                        = 2000 //服务端已初始化tls连接
	SERVER_RECEIVED_CLIENT_HELLO_STATE       = 2001 //服务端已接受client hello
	SERVER_SENT_SERVER_HELLO_STATE           = 2002 //服务端已发送server hello
	SERVER_RECEIVE_CLIENT_KEY_EXCHANGE_STATE = 2003 //服务端已接受到通信密钥
	SERVER_SENT_FINISHED_STATE               = 2004 //服务端已发送开启加密通信
	SERVER_NO_ENCRYPT_CONNECTION_STATE       = 2005 //服务端已建立非加密连接
	SERVER_ENCRYPTED_CONNECTION_STATE        = 2006 //服务端已建立加密连接
	SERVER_CLOSED_STATE                      = 2007 //服务端已关闭tls连接

)

const (
	//每种握手消息都会有一个type，所有的alert， type都为alert
	CLIENT_HELLO_TYPE        = "CLIENT_HELLO_TYPE"
	CLIENT_KEY_EXCHANGE_TYPE = "CLIENT_KEY_EXCHANGE_TYPE"
	CLIENT_CLOSE_NOTIFY_TYPE = "CLIENT_CLOSE_NOTIFY_TYPE"

	SERVER_HELLO_TYPE    = "SERVER_HELLO_TYPE"
	SERVER_FINISHED_TYPE = "SERVER_FINISHED_TYPE"

	CLIENT_APP_DATA_TYPE = "CLIENT_APP_DATA_TYPE"
	SERVER_APP_DATA_TYPE = "SERVER_APP_DATA_TYPE"

	ALERT_TYPE = "ALERT_TYPE"
)

//定义handshakeCode 一个handshake或是一个alert 视作一个handshake
const (
	//每种握手消息都会有一个code，客户端或服务端接收到一个握手消息，根据code可能引起状态的转变
	CLIENT_HELLO_CODE        = 10
	CLIENT_KEY_EXCHANGE_CODE = 11
	CLIENT_CLOSE_NOTIFY_CODE = 12

	SERVER_HELLO_CODE    = 20
	SERVER_FINISHED_CODE = 21

	CLIENT_APP_DATA_CODE = 30
	SERVER_APP_DATA_CODE = 31

	ALERT_1_CODE = 40
	//下面是预留的alert 的code
	//下面是非握手消息的actionCode
)

//定义路由
//var RouteMap map[int]string = map[int]string{
//	CLIENT_HELLO_CODE: "/handleClientHello",
//}

const REQUEST_URL = "http://127.0.0.1:8086/test"
const LISTEN_URL = "localhost:8086"
const LISTEN_TLS = "/handleTLS/"

func GetHSRequestRoute() string {
	return REQUEST_URL + LISTEN_TLS
}
