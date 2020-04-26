package gosdk

import (
	"encoding/json"
	"github.com/pretty66/gosdk/errno"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type TlsConfig struct {
	SessionId             string                `json:"sessionId"`
	IsClient              bool                  `json:"isClient"` //标志该tlsConfig持有者是客户端还是服务端
	CurrentInfo           Idn                   `json:"currentInfo"`
	TargetInfo            Idn                   `json:"targetInfo"`
	RequestUrl            string                `json:"requestUrl"`
	HandshakeState        StateMachineInterface `json:"handshakeState"`    //握手状态 与状态机模式有关
	IsEncryptRequired     bool                  `json:"isEncryptRequired"` //是否需要加密 如果有一方该字段为true，则开启加密通信
	IsCertRequired        bool                  `json:"isCertRequired"`    //客户端初始化TLSConfig时可以指定是否需要证书
	State                 int                   `json:"state"`             //TLS连接的状态
	CipherSuites          []int                 `json:"cipherSuites"`      //客户端或是服务端持有的加密套件列表
	CipherSuite           int                   `json:"cipherSuite"`       //协商时由服务端指定的加密套件
	Time                  time.Time             `json:"time"`              //该TLSConfig创建的时间
	Timeout               time.Duration         `json:"timeout"`           //TLS超时时间
	Randoms               []string              `json:"randoms"`           //随机数数组，保留做以后扩展
	PrivateKey            []byte                `json:"privateKey"`
	PublicKey             []byte                `json:"publicKey"`
	SymmetricKey          []byte                `json:"symmetricKey"`          //通信密钥 由指定的cipherSuite生成
	SymmetricKeyCreatedAt time.Time             `json:"symmetricKeyCreatedAt"` //通信密钥创建的时间
	SymmetricKeyExpiresAt time.Time             `json:"symmetricKeyExpiresAt"` //通信密钥过期的时间
	IsReuse               bool                  `json:"isReuse"`               //是否可以复用该配置
	Cert                  []byte                `json:"cert"`                  //证书 客户端有两种证书获取方式 ：1 从server hello中获取 2 从部署时指定的路径获取
	CertChain             [][]byte              `json:"certChain"`             //证书验证链
	CertLoader            CertLoaderInterface   `json:"certLoaderInterface"`   //用户传入的证书工厂，可根据指定的cipherSuite获取相应的证书和证书验证链
	HandshakeMsgs         map[int]Handshake     `json:"handshakeMsgs"`         //协商密钥的扩展消息，包括client hello + server hello + client key exchange
	Logs                  []string              `json:"logs"`                  //日志记录，留作扩展
}

type TlsConfigInterface interface {
}

const (
	TLS_STATE_ACTIVING = 1 //TLS激活中
	TLS_STATE_BROKE    = 0 //TLS断开
)

var _sessionMap map[string]TlsConfig
var _currentTlsConfigFilePath string

const CLIENT_TLS_CONFIG_FILE_PATH = "clientTlsConfig.txt"
const SERVER_TLS_CONFIG_FILE_PATH = "serverTlsConfig.txt"

//从指定的路径中获取
func GetSessionMapFromFIle(tlsConfigFilePath string) (out map[string]TlsConfig, err error) {
	if _sessionMap == nil || _currentTlsConfigFilePath != tlsConfigFilePath {
		data, err := ioutil.ReadFile(tlsConfigFilePath)
		if err != nil {
			return out, errno.FILE_READ_ERROR.Add(err.Error())
		}
		if len(data) == 0 {
			return out, err
		}
		err = json.Unmarshal(data, &_sessionMap)
		if err != nil {
			return out, errno.JSON_ERROR.Add(err.Error())
		}
		_currentTlsConfigFilePath = tlsConfigFilePath
	}
	return _sessionMap, err
}

func SaveTLSConfigToTlsConfigMap(tlsConfigFilePath string, tlsConfig TlsConfig) error {
	currentTlsConfigMap, err := GetSessionMapFromFIle(tlsConfigFilePath)
	if err != nil {
		return errno.FILE_READ_ERROR.Add(err.Error())
	}
	currentTlsConfigMap[tlsConfig.SessionId] = tlsConfig
	return err
}

func SaveTLSConfigToFile(tlsConfigFilePath string) (err error) {
	currentSessionMap, err := GetSessionMapFromFIle(tlsConfigFilePath)
	if err != nil {
		return errno.FILE_READ_ERROR.Add(err.Error())
	}
	if len(currentSessionMap) == 0 {
		return err
	}
	configMapMarshal, err := json.Marshal(currentSessionMap)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(tlsConfigFilePath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return errno.FILE_WRITE_ERROR.Add(err.Error())
	}
	n, err := file.Write(configMapMarshal)
	if err != nil {
		return errno.FILE_WRITE_ERROR.Add(err.Error())
		log.Fatal(n)
	}
	return

}

//根据sessionId实例化一个tlsConfig
func ReuseSession(sessionId, filepath string) *TlsConfig {
	return nil
}

//传入连个节点数据，判断是否需要开启加密通信
func GetNeedCrypt(testFlag bool) bool {
	return testFlag
}

func GetHasSymmetricKey(testFlag bool) bool {
	return testFlag
}

func IfClientRequiredCert() bool {
	return true
}

func ClientInitTlsConfig() {
	config := &TlsConfig{}
	config.IsClient = true
	//config.handshakeState =
}
