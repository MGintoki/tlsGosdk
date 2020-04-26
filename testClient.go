package gosdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/cache"
	"github.com/pretty66/gosdk/errno"
	"net/http"
	"strconv"
)

type TlsClient struct {
	CurrentInfo Idn        `json:"currentInfo"`
	TargetInfo  Idn        `json:"targetInfo"`
	RequestPath string     `json:"requestPath"`
	TlsConfig   *TlsConfig `json:"tlsConfig"`
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Inside HelloServer handler")
	fmt.Fprintf(w, "Hello,"+req.URL.Path[1:])
}

//func main() {
//	http.HandleFunc("/", HelloServer)
//	err := http.ListenAndServe("localhost:8080", nil)
//	if err != nil {
//		log.Fatal("ListenAndServe: ", err.Error())
//	}
//}

func (c *TlsClient) Exec(method,
	reqUrl string,
	data map[string]interface{},
	contentType string,
	file *fileStruct) (out []byte, err error) {

	//如果需要tls，则进行tls配置
	if ifNeedTls(c.CurrentInfo, c.TargetInfo) {
		tlsConfig, err := GetTlsConfigByIdns(c.CurrentInfo, c.TargetInfo)
		if err != nil {
			return out, err
		}
		//如果没有已经存在的配置，就新建一个
		if tlsConfig == nil {
			i, err := c.initTlsConfig(reqUrl)
			if err != nil {
				return nil, err
			}
			fmt.Println("init tls config success")
			if c.TlsConfig.HandshakeState.currentState() != CLIENT_INIT_STATE {
				return out, errno.INVALID_HANDSHAKE_STATE_ERROR.Add("Current State -> " + strconv.Itoa(c.TlsConfig.HandshakeState.currentState()))
			}
			err = c.startTlsHandshake(i)
			if err != nil {
				return out, errno.HANDSHAKE_ERROR.Add(err.Error())
			}
			if c.TlsConfig.HandshakeState.currentState() != CLIENT_ENCRYPTED_CONNECTION_STATE {
				return out, errno.INVALID_HANDSHAKE_STATE_ERROR.Add("Current State -> " + strconv.Itoa(c.TlsConfig.HandshakeState.currentState()))
			}

			//如果存在可用的配置，复用
		} else {

		}
		data = c.encryptData(data, tlsConfig)
	}

	return
}

//初始化tls配置
func (c *TlsClient) initTlsConfig(reqUrl string) (tlsConfig *TlsConfig, err error) {
	return nil, nil
}

func (c *TlsClient) startTlsHandshake(tlsConfig *TlsConfig) (err error) {
	return nil
}

func (c *TlsClient) encryptData(data map[string]interface{}, tlsConfig *TlsConfig) (out map[string]interface{}) {
	return nil
}

func ifNeedTls(currentInfo Idn, targetInfo Idn) bool {
	return true
}

//从缓存中获取到Tls配置map,该map由json.marshal序列化成字符串后，以base64编码的形式存在缓存中
//如果取的时候，发现缓存中没有这个str，则新建空的tlsConfigMap并返回
func GetTlsConfigMap() (tlsConfigMap map[string]TlsConfig, err error) {
	_cache := cache.NewCache(false, 0)
	tlsConfigMapStr := _cache.Get(TLS_CONFIG_MAP)
	if tlsConfigMapStr == "" {
		tlsConfigMapTmp := map[string]TlsConfig{}
		tlsConfigMapByte, err := json.Marshal(tlsConfigMapTmp)
		if err != nil {
			return nil, errno.JSON_ERROR.Add("init tlsConfigMap failed")
		}
		tlsConfigMapStr := base64.StdEncoding.EncodeToString(tlsConfigMapByte)
		_cache := cache.NewCache(false, 0)
		_cache.Set(TLS_CONFIG_MAP, tlsConfigMapStr, 0)
		return tlsConfigMapTmp, err
	}
	tlsConfigMapByte, err := base64.StdEncoding.DecodeString(tlsConfigMapStr)
	if err != nil {
		return nil, errno.BASE64_DECODE_ERROER.Add(err.Error())
	}
	err = json.Unmarshal(tlsConfigMapByte, &tlsConfigMap)
	if err != nil {
		return nil, errno.JSON_ERROR.Add(err.Error())
	}
	return tlsConfigMap, err
}

//在缓存中设置TlsConfigMap
func SetTlsConfigMap(tlsConfigMap map[string]TlsConfig) (err error) {
	tlsConfigMapByte, err := json.Marshal(tlsConfigMap)
	if err != nil {
		return errno.JSON_ERROR.Add(err.Error())
	}
	var testMap TlsConfig
	err = json.Unmarshal(tlsConfigMapByte, &testMap)
	fmt.Println(testMap)
	tlsConfigMapStr := base64.StdEncoding.EncodeToString(tlsConfigMapByte)
	_cache := cache.NewCache(false, 0)
	_cache.Set(TLS_CONFIG_MAP, tlsConfigMapStr, 10000)
	return
}

//从缓存中，通过sessionId获取到TlsConfig
func GetTlsConfigBySessionId(sessionId string) (tlsConfig *TlsConfig, err error) {
	tlsConfigMap, err := GetTlsConfigMap()
	if err != nil {
		return
	}
	if _, ok := tlsConfigMap[sessionId]; ok {
		tmpTlsConfig := tlsConfigMap[sessionId]
		//需要检测是否过期，过期的话返回nil
		return &tmpTlsConfig, err
	}
	return nil, err
}

func GetTlsConfigByIdns(currentInfo Idn, targetInfo Idn) (tlsConfig *TlsConfig, err error) {
	tlsConfigMap, err := GetTlsConfigMap()
	if err != nil {
		return tlsConfig, err
	}
	for _, v := range tlsConfigMap {
		if currentInfo.AppKey == v.CurrentInfo.AppKey && currentInfo.Channel == v.CurrentInfo.Channel && targetInfo.AppKey == v.TargetInfo.AppKey && targetInfo.Channel == v.TargetInfo.Channel {
			//需要检测是否过期，过期的话返回nil
			return &v, nil
		}
	}
	return nil, err
}

func SaveTlsConfig(tlsConfig *TlsConfig) (err error) {
	tlsConfigMap, err := GetTlsConfigMap()
	tlsConfigMap[tlsConfig.SessionId] = *tlsConfig
	err = SetTlsConfigMap(tlsConfigMap)
	return
}

const (
	TLS_CONFIG_MAP = "clientTlsConfigMap"
)
