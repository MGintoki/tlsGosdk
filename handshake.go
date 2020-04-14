package gosdk

import "time"

type handshake struct {
	version       string
	handshakeType string //握手类型，根据该类型判断下面哪个指针已赋值
	handShakeCode string
	sessionId     string
	sendTime      time.Time //发送时间

	//clientHello       *clientHello
	//serverHello       *serverHello
	//clientKeyExchange *clientKeyExchange
	//serverFinished    *serverFinished
}

type clientHello struct {
	handshake
	isClientEncryptRequired bool //是否需要加密
	isCertRequired          bool //是否需要服务端证书，不需要的话，说明客户端从部署指定路径获取
	cipherSuites            []*cipherSuite
}

type serverHello struct {
	handshake
	isServerEncryptRequired bool
	cipher                  *cipherSuite
	cert                    string   //服务端TLS证书
	certVerifyChain         []string //服务端TLS证书验证链
}

type clientKeyExchange struct {
	handshake
	symmetricKey *symmetricKey
	MAC          string
}

type serverFinished struct {
	handshake
	sessionId string
	MAC       string
}

type appData struct {
	handshake
	data map[string]interface{}
	MAC  string
}

type alert struct {
	handshake
	alert string
	msg   string
}

//TLS状态转换机，将TLS之间的状态转换封装到该方法中
func StateMachine(currentHSState string, handshakeCode string) string {
	return ""
}

//客户端与服务端定义状态码
const (
	CLIENT_INIT_STATE            = "CLIENT_INIT"                  //客户端已初始化tls连接
	CLIENT_SENT_CLIENT_HELLO     = "CLIENT_SENT_CLIENT_HELLO"     //客户端已发送client hello
	CLIENT_RECEIVED_SERVER_HELLO = "CLIENT_RECEIVED_SERVER_HELLO" // 客户端已接受到server hello
	CLIENT_SENT_KEY_EXCHANGE     = "CLIENT_SENT_KEY_EXCHANGE"     //客户端已发送通信密钥
	CLIENT_NO_ENCRYPT_CONNECTION = "CLIENT_NO_ENCRYPT_CONNECTION" //客户端已建立非加密连接
	CLIENT_ENCRYPTED_CONNECTION  = "CLIENT_ENCRYPTED_CONNECTION"  //客户端已建立加密连接
	CLIENT_FINISHED              = "CLIENT_FINISHED"              //客户端已关闭tls连接

	SERVER_INIT_STATE                  = "SERVER_INIT_STATE"                  //服务端已初始化tls连接
	SERVER_RECEIVED_CLIENT_HELLO       = "SERVER_RECEIVED_CLIENT_HELLO"       //服务端已接受client hello
	SERVER_SENT_SERVER_HELLO           = "SERVER_SENT_SERVER_HELLO"           //服务端已发送server hello
	SERVER_RECEIVE_CLIENT_KEY_EXCHANGE = "SERVER_RECEIVE_CLIENT_KEY_EXCHANGE" //服务端已接受到通信密钥
	SERVER_SENT_FINISHED               = "SERVER_SENT_FINISHED"               //服务端已发送开启加密通信
	SERVER_NO_ENCRYPT_CONNECTION       = "SERVER_NO_ENCRYPT_CONNECTION"       //服务端已建立非加密连接
	SERVER_ENCRYPTED_CONNECTION        = "SERVER_ENCRYPTED_CONNECTION"        //服务端已建立加密连接
	SERVER_FINISHED                    = "SERVER_FINISHED"                    //服务端已关闭tls连接
)

//定义handshakeCode 一个handshake或是一个alert 视作一个handshake
const (
	//每种握手消息都会有一个code，客户端或服务端接收到一个握手消息，根据code可能引起状态的转变
	CLIENT_HELLO_CODE        = "CLIENT_HELLO_CODE"
	CLIENT_KEY_EXCHANGE_CODE = "CLIENT_KEY_EXCHANGE_CODE"
	CLIENT_CLOSE_NOTIFY_CODE = "CLIENT_CLOSE_NOTIFY_CODE"

	SERVER_HELLO_CODE    = "SERVER_HELLO_CODE"
	SERVER_FINISHED_CODE = "SERVER_FINISHED_CODE"

	APP_DATA_CODE = "APP_DATA_CODE"

	//下面是预留的alert 的code

)
