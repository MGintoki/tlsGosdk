package gosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/pretty66/gosdk/errno"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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

	tlsConfig, err := GetClientTlsConfigByIdns(c.CurrentInfo, c.TargetInfo)
	if err != nil {
		return out, err
	}

	//如果需要tls，则进行tls配置

	//如果没有已经存在的配置，就新建一个
	if tlsConfig == nil {
		tlsConfig, err = c.initTlsConfig(reqUrl)
		if err != nil {
			return nil, err
		}
		fmt.Println("init tls config success")
		//如果经过初始化方法，tlsConfig状态不为初始化完成，返回
		if tlsConfig.HandshakeState.currentState() != CLIENT_INIT_STATE {
			return out, errno.INVALID_HANDSHAKE_STATE_ERROR.Add("Current State -> " + strconv.Itoa(c.TlsConfig.HandshakeState.currentState()))
		}
		//没有配置的话，要先和服务端进行握手
		err = c.startTlsHandshake(tlsConfig)
		if err != nil {
			return out, errno.HANDSHAKE_ERROR.Add(err.Error())
		}
		//如果握手完成后，状态不是 1：加密通信状态 2：非加密通信状态 则返回
		if tlsConfig.HandshakeState.currentState() != CLIENT_ENCRYPTED_CONNECTION_STATE && tlsConfig.HandshakeState.currentState() != CLIENT_NO_ENCRYPT_CONNECTION_STATE {
			return nil, errno.HANDSHAKE_ERROR.Add("handshake state invalid")
		}
		//握手结束后保存tlsConfig到缓存里，方便复用
		err := SaveClientTlsConfig(tlsConfig)
		if err != nil {
			return nil, err
		}
	}

	if tlsConfig.IsEncryptRequired == true && tlsConfig.HandshakeState.currentState() == CLIENT_ENCRYPTED_CONNECTION_STATE {
		//data, err = c.encryptData(data, tlsConfig, contentType, file)
		//if err != nil {
		//	return nil, err
		//}
		dataMarshal, err := json.Marshal(data)
		if err != nil {
			return nil, errno.JSON_ERROR.Add(err.Error())
		}
		dataEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(dataMarshal, tlsConfig.SymmetricKey)
		if err != nil {
			return nil, errno.SYMMETRIC_KEY_ENCRYPT_ERROR.Add(err.Error())
		}
		//appData里的数据，转换成字节流后base64压缩成字符串
		dataStr := base64.StdEncoding.EncodeToString(dataEncrypted)
		MAC := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateMAC(dataMarshal)
		MACEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(MAC, tlsConfig.SymmetricKey)
		MACEncryptedToStr := base64.StdEncoding.EncodeToString(MACEncrypted)
		if err != nil {
			return nil, errno.SYMMETRIC_KEY_ENCRYPT_ERROR.Add(err.Error())
		}
		appData := &AppData{
			Data: dataStr,
			MAC:  MACEncryptedToStr,
		}
		handshake := &Handshake{
			Version:       "",
			HandshakeType: 0,
			ActionCode:    CLIENT_APP_DATA_CODE,
			SessionId:     tlsConfig.SessionId,
			SendTime:      time.Time{},
			AppData:       appData,
		}
		//发送appData并接收服务端响应
		//默认发送json格式，由中间件接收到appData之后，根据header里的contentType重新设置request交给服务端
		//resHandshake, err := tlsConfig.HandshakeState.handleAction(tlsConfig, handshake, handshake.ActionCode)
		resHandshake, err := c.sendHandshake(tlsConfig, handshake)
		resHandshake, err = tlsConfig.HandshakeState.handleAction(tlsConfig, handshake, resHandshake.ActionCode)

		if err != nil {
			return nil, errno.HANDSHAKE_ERROR.Add(err.Error())
		}
		dataEncryptedStr := resHandshake.AppData.Data
		dataEncryptedByte, err := base64.StdEncoding.DecodeString(dataEncryptedStr)
		if err != nil {
			return nil, errno.BASE64_DECODE_ERROER.Add(err.Error())
		}
		dataPlainText, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(dataEncryptedByte, tlsConfig.SymmetricKey)
		if err != nil {
			return nil, errno.SYMMETRIC_KEY_DECRYPT_ERROR
		}
		err = SaveClientTlsConfig(tlsConfig)
		if err != nil {
			return nil, err
		}
		return dataPlainText, err
	}

	//如果部署指定，不需要加密，则发送clientHello（预检请求）

	//发送数据 （如果数据是加密的，则需要设置请求头sessionId和handshakeMsg

	return
}

func (c *TlsClient) parseBody(
	method,
	reqUrl string,
	data map[string]interface{},
	contentType string,
	file *fileStruct,
) (req *http.Request, err error) {
	// todo 多文件上传
	method = strings.ToUpper(method)

	switch contentType {
	case CONTENT_TYPE_FORM:
		theData := url.Values{}
		for k, v := range data {
			theData.Set(k, fmt.Sprint(v))
		}
		body := strings.NewReader(theData.Encode())
		req, err = http.NewRequest(method, reqUrl, body)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return
		}
		req.Header.Set("Content-Type", CONTENT_TYPE_FORM)
	case CONTENT_TYPE_JSON:
		bytesData, err := json.Marshal(data)
		if err != nil {
			return nil, errno.JSON_ERROR.Add(err.Error())
		}
		body := bytes.NewReader(bytesData)
		req, err = http.NewRequest(method, reqUrl, body)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return req, err
		}
		req.Header.Set("Content-Type", CONTENT_TYPE_JSON)

	case CONTENT_TYPE_MULTIPART:
		buff := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(buff)
		// 写入其他参数
		for k, v := range data {
			err := bodyWriter.WriteField(k, fmt.Sprint(v))
			if err != nil {
				return nil, errno.DATA_WRONG_TYPE.Add(err.Error())
			}
		}
		if file != nil {
			// 写入文件
			fileWriter, err := bodyWriter.CreateFormFile(file.fileKey, file.fileName)
			if err != nil {
				return nil, errno.SDK_ERROR.Add(err.Error())
			}

			_, err = io.Copy(fileWriter, file.file)
			if err != nil {
				return nil, errno.SDK_ERROR.Add(err.Error())
			}
		}
		req, err = http.NewRequest(method, reqUrl, buff)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return
		}
		req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	}
	return
}

//初始化tls配置
func (c *TlsClient) initTlsConfig(reqUrl string) (out *TlsConfig, err error) {
	tlsConfig := &TlsConfig{
		SessionId:             "",
		IsClient:              true,
		CurrentInfo:           c.CurrentInfo,
		TargetInfo:            c.TargetInfo,
		RequestUrl:            reqUrl,
		HandshakeState:        nil,
		IsEncryptRequired:     c.ifNeedTls(c.CurrentInfo, c.TargetInfo),
		IsCertRequired:        c.isCertRequired(c.CurrentInfo, c.TargetInfo),
		State:                 TLS_STATE_ACTIVING,
		CipherSuites:          c.getCipherSuites(c.CurrentInfo, c.TargetInfo),
		CipherSuite:           0,
		Time:                  time.Time{},
		Timeout:               0,
		Randoms:               []string{},
		PrivateKey:            nil,
		PublicKey:             nil,
		SymmetricKey:          nil,
		SymmetricKeyCreatedAt: time.Time{},
		SymmetricKeyExpiresAt: time.Time{},
		Cert:                  nil,
		CertChain:             nil,
		CertLoader:            nil,
		HandshakeMsgs:         map[int]Handshake{},
		Logs:                  []string{},
	}
	timeOut, KeyTimeOut, isReuse, err := c.getInitInfo(c.CurrentInfo, c.TargetInfo)
	if err != nil {
		return nil, err
	}
	tlsConfig.Timeout = timeOut
	tlsConfig.SymmetricKeyExpiresAt = tlsConfig.SymmetricKeyCreatedAt.Add(KeyTimeOut)
	tlsConfig.IsReuse = isReuse
	cert, certChain, publicKey, err := c.getCert(c.CurrentInfo, c.TargetInfo)
	if err != nil {
		return nil, err
	}
	tlsConfig.Cert = cert
	tlsConfig.CertChain = certChain
	tlsConfig.PublicKey = publicKey
	tlsConfig.HandshakeState = &ClientInitState{}
	return tlsConfig, err
}

func (c *TlsClient) startTlsHandshake(tlsConfig *TlsConfig) (err error) {
	//发送clientHello
	clientHello, err := tlsConfig.HandshakeState.handleAction(tlsConfig, nil, CLIENT_HELLO_CODE)
	clientHelloHSOut, err := c.sendHandshake(tlsConfig, clientHello)
	tlsConfig.HandshakeState = &ClientSentClientHelloState{}
	tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE] = *clientHello
	if err != nil {
		return err
	}
	if clientHelloHSOut.ActionCode == SERVER_HELLO_CODE && clientHelloHSOut.ServerHello.IsServerEncryptRequired {
		tlsConfig.HandshakeState = &ClientReceivedServerHelloState{}
		tlsConfig.IsEncryptRequired = true
	} else if clientHelloHSOut.ActionCode == SERVER_HELLO_CODE && clientHelloHSOut.ServerHello.IsServerEncryptRequired == false {
		tlsConfig.HandshakeState = &ClientNoEncryptConnectionState{}
		tlsConfig.IsEncryptRequired = false
		return
	}
	fmt.Println("client hello done")
	clietKeyExchangeHS, err := tlsConfig.HandshakeState.handleAction(tlsConfig, clientHelloHSOut, clientHelloHSOut.ActionCode)
	clientKeyExchangeHSOut, err := c.sendHandshake(tlsConfig, clietKeyExchangeHS)
	tlsConfig.HandshakeState = &ClientSentKeyExchangeState{}
	if err != nil {
		return errno.HANDSHAKE_ERROR.Add(err.Error())
	}
	if clientKeyExchangeHSOut.ActionCode == SERVER_FINISHED_CODE && tlsConfig.IsEncryptRequired {
		tlsConfig.HandshakeState = &ClientReceivedServerFinishedState{}
		tlsConfig.HandshakeState = &ClientEncryptedConnectionState{}
	} else {
		return errno.INVALID_HANDSHAKE_STATE_ERROR
	}

	return nil
}

func (c *TlsClient) sendHandshake(tlsConfig *TlsConfig, handshake *Handshake) (out *Handshake, err error) {
	//以后换成getClient方法
	client := http.Client{}
	reqUrl := tlsConfig.RequestUrl
	hsByte, err := json.Marshal(handshake)
	if err != nil {
		return out, err
	}

	request, err := http.NewRequest("POST", reqUrl, bytes.NewReader(hsByte))
	if err != nil {
		return nil, errno.REQUEST_SETING_ERROR.Add(err.Error())
	}
	if handshake.ActionCode == CLIENT_HELLO_CODE {
		request.Method = "OPTION"
	}
	request.Header.Set("Content-Type", CONTENT_TYPE_JSON)
	request.Header.Set("HandShake-Code", strconv.Itoa(handshake.ActionCode))
	if tlsConfig.SessionId != "" {
		request.Header.Set("Session-Id", tlsConfig.SessionId)
	}
	response, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	handshakeCode := response.Header.Get("HandShake-Code")
	//如果请求头handshakeCode为serverAppdata，需要将其解析成handshake类型
	if handshakeCode == strconv.Itoa(SERVER_APP_DATA_CODE) {
		tmpMap := map[string]interface{}{}
		err = json.NewDecoder(response.Body).Decode(&tmpMap)
		fmt.Println(tmpMap)
		handshakeStr := tmpMap["data"].(string)
		handshakeStrDecodeByte, _ := base64.StdEncoding.DecodeString(handshakeStr)
		err = json.Unmarshal(handshakeStrDecodeByte, &out)
		return out, err
	}
	err = json.NewDecoder(response.Body).Decode(&out)
	return out, err
}

//func (c *TlsClient) startTlsHandshake(tlsConfig *TlsConfig) (err error) {
//	//发送clientHello
//	clientHelloHSOut, err := tlsConfig.HandshakeState.handleAction(tlsConfig, nil, CLIENT_HELLO_CODE)
//	if err != nil {
//		return err
//	}
//	if clientHelloHSOut.ActionCode == SERVER_HELLO_CODE && clientHelloHSOut.ServerHello.IsServerEncryptRequired {
//		tlsConfig.HandshakeState = &ClientReceivedServerHelloState{}
//		tlsConfig.IsEncryptRequired = true
//	} else if clientHelloHSOut.ActionCode == SERVER_HELLO_CODE && clientHelloHSOut.ServerHello.IsServerEncryptRequired == false {
//		tlsConfig.HandshakeState = &ClientNoEncryptConnectionState{}
//		tlsConfig.IsEncryptRequired = false
//		return
//	}
//	fmt.Println("client hello done")
//	clientKeyExchangeHSOut, err := tlsConfig.HandshakeState.handleAction(tlsConfig, clientHelloHSOut, clientHelloHSOut.ActionCode)
//	if err != nil {
//		return errno.HANDSHAKE_ERROR.Add(err.Error())
//	}
//	if clientKeyExchangeHSOut.ActionCode == SERVER_FINISHED_CODE && tlsConfig.IsEncryptRequired {
//		tlsConfig.HandshakeState = &ClientEncryptedConnectionState{}
//	} else {
//		return errno.INVALID_HANDSHAKE_STATE_ERROR
//	}
//
//	return nil
//}

func (c *TlsConfig) SendHandshake(handshake *Handshake) (out *Handshake, err error) {
	//以后换成getClient方法
	client := http.Client{}
	reqUrl := c.RequestUrl
	hsByte, err := json.Marshal(handshake)
	if err != nil {
		return out, err
	}

	request, err := http.NewRequest("POST", reqUrl, bytes.NewReader(hsByte))
	if err != nil {
		return nil, errno.REQUEST_SETING_ERROR.Add(err.Error())
	}
	if handshake.ActionCode == CLIENT_HELLO_CODE {
		request.Method = "OPTION"
	}
	request.Header.Set("Content-Type", CONTENT_TYPE_JSON)
	request.Header.Set("HandShake-Code", strconv.Itoa(handshake.ActionCode))
	if c.SessionId != "" {
		request.Header.Set("Session-Id", c.SessionId)
	}
	response, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	handshakeCode := response.Header.Get("HandShake-Code")
	//如果请求头handshakeCode为serverAppdata，需要将其解析成handshake类型
	if handshakeCode == strconv.Itoa(SERVER_APP_DATA_CODE) {
		tmpMap := map[string]interface{}{}
		err = json.NewDecoder(response.Body).Decode(&tmpMap)
		fmt.Println(tmpMap)
		handshakeStr := tmpMap["data"].(string)
		handshakeStrDecodeByte, _ := base64.StdEncoding.DecodeString(handshakeStr)
		err = json.Unmarshal(handshakeStrDecodeByte, &out)
		return out, err
	}
	err = json.NewDecoder(response.Body).Decode(&out)
	return out, err

}

//func (c *TlsClient) encryptData(data map[string]interface{}, tlsConfig *TlsConfig, contentType string, file *fileStruct) (out map[string]interface{}, err error) {
//	outMap := map[string]interface{}{}
//	switch contentType {
//	case CONTENT_TYPE_FORM:
//		//contentType为json时，将数据序列化在加密，得到的字节数组采用base64编码成string返回
//	case CONTENT_TYPE_JSON:
//		dataByte, err := json.Marshal(data)
//		if err != nil {
//			return nil, errno.JSON_ERROR.Add(err.Error())
//		}
//		cipherText, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(dataByte, tlsConfig.SymmetricKey)
//		if err != nil {
//			return nil, err
//		}
//		cipherTextEncode := base64.StdEncoding.EncodeToString(cipherText)
//		outMap["encryptedData"] = cipherTextEncode
//		return outMap, err
//	case CONTENT_TYPE_MULTIPART:
//		return
//	default:
//		return nil, errno.CONTENT_TYPE_ERROR.Add("Current ContentType " + contentType + " Not Allowed")
//	}
//	return
//}

func (c *TlsClient) ifNeedTls(currentInfo Idn, targetInfo Idn) bool {
	//if currentInfo.AppKey != targetInfo.AppKey {
	//	return true
	//}
	if currentInfo.AppKey != "123456" {
		return true
	}
	return false
}

func (c *TlsClient) isCertRequired(currentInfo Idn, targetInfo Idn) bool {
	//if currentInfo.AppKey != targetInfo.AppKey {
	//	return true
	//}
	if currentInfo.AppKey != "123456" {
		return true
	}
	return false
}

func (c *TlsClient) getInitInfo(currentInfo Idn, targetInfo Idn) (timeOut time.Duration, keyTimeOut time.Duration, isReuse bool, err error) {
	return TIMEOUT * time.Second, KEY_TIME_OUT * time.Hour, true, nil
}
func (c *TlsClient) getCert(currentInfo Idn, targetInfo Idn) (outCert []byte, outCertChain []byte, outPublicKey []byte, err error) {
	return nil, nil, nil, nil
}

func (c *TlsClient) getCipherSuites(currentInfo Idn, targetInfo Idn) (out []int) {
	out = append(out, cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"])
	out = append(out, cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"])
	return
}

//
//var _clientTlsConfigMap map[string]TlsConfig
//
//func GetClientTlsConfigMap() map[string]TlsConfig {
//	if _clientTlsConfigMap == nil {
//		_clientTlsConfigMap = map[string]TlsConfig{}
//	}
//	return _clientTlsConfigMap
//}
//func GetClientTlsConfigByIdns(currentInfo Idn, targetInfo Idn) (tlsConfig *TlsConfig, err error) {
//	tlsConfigMap := GetClientTlsConfigMap()
//	for _, v := range tlsConfigMap {
//		if currentInfo.AppKey == v.CurrentInfo.AppKey && currentInfo.Channel == v.CurrentInfo.Channel && targetInfo.AppKey == v.TargetInfo.AppKey && targetInfo.Channel == v.TargetInfo.Channel {
//			return &v, nil
//		}
//	}
//	return nil, nil
//}
//
//func SaveClientTlsConfig(tlsConfig *TlsConfig) error {
//	tlsConfigMap := GetClientTlsConfigMap()
//	tlsConfigMap[tlsConfig.SessionId] = *tlsConfig
//	return nil
//}

////从缓存中，通过sessionId获取到TlsConfig
//func GetTlsConfigBySessionId(sessionId string) (tlsConfig *TlsConfig, err error) {
//	tlsConfigMap, err := GetTlsConfigMap()
//	if err != nil {
//		return
//	}
//	if _, ok := tlsConfigMap[sessionId]; ok {
//		tmpTlsConfig := tlsConfigMap[sessionId]
//		//需要检测是否过期，过期的话返回nil
//		return &tmpTlsConfig, err
//	}
//	return nil, err
//}

//
//func GetClientTlsConfigByIdns(currentInfo Idn, targetInfo Idn) (tlsConfig *TlsConfig, err error) {
//	tlsConfigMap, err := GetTlsConfigMap()
//	if err != nil {
//		return tlsConfig, err
//	}
//	for _, v := range tlsConfigMap {
//		if currentInfo.AppKey == v.CurrentInfo.AppKey && currentInfo.Channel == v.CurrentInfo.Channel && targetInfo.AppKey == v.TargetInfo.AppKey && targetInfo.Channel == v.TargetInfo.Channel {
//			//需要检测是否过期，过期的话返回nil
//			return &v, nil
//		}
//	}
//	return nil, err
//}
//
//func SaveClientTlsConfig(tlsConfig *TlsConfig) (err error) {
//	tlsConfigMap, err := GetTlsConfigMap()
//	tlsConfigMap[tlsConfig.SessionId] = *tlsConfig
//	err = SetTlsConfigMap(tlsConfigMap)
//	return
//}
//
//const (
//	TLS_CONFIG_MAP = "clientTlsConfigMap"
//)
//
////从缓存中获取到Tls配置map,该map由json.marshal序列化成字符串后，以base64编码的形式存在缓存中
////如果取的时候，发现缓存中没有这个str，则新建空的tlsConfigMap并返回
//func GetTlsConfigMap() (tlsConfigMap map[string]TlsConfig, err error) {
//	_cache := cache.NewCache(false, 0)
//	tlsConfigMapStr := _cache.Get(TLS_CONFIG_MAP)
//	if tlsConfigMapStr == "" {
//		tlsConfigMapTmp := map[string]TlsConfig{}
//		tlsConfigMapByte, err := json.Marshal(tlsConfigMapTmp)
//		if err != nil {
//			return nil, errno.JSON_ERROR.Add("init tlsConfigMap failed")
//		}
//		tlsConfigMapStr := base64.StdEncoding.EncodeToString(tlsConfigMapByte)
//		_cache := cache.NewCache(false, 0)
//		_cache.Set(TLS_CONFIG_MAP, tlsConfigMapStr, 0)
//		return tlsConfigMapTmp, err
//	}
//	tlsConfigMapByte, err := base64.StdEncoding.DecodeString(tlsConfigMapStr)
//	if err != nil {
//		return nil, errno.BASE64_DECODE_ERROER.Add(err.Error())
//	}
//	err = json.Unmarshal(tlsConfigMapByte, &tlsConfigMap)
//	if err != nil {
//		return nil, errno.JSON_ERROR.Add(err.Error())
//	}
//	return tlsConfigMap, err
//}
//
////在缓存中设置TlsConfigMap
//func SetTlsConfigMap(tlsConfigMap map[string]TlsConfig) (err error) {
//	tlsConfigMapByte, err := json.Marshal(tlsConfigMap)
//	if err != nil {
//		return errno.JSON_ERROR.Add(err.Error())
//	}
//	var testMap TlsConfig
//	err = json.Unmarshal(tlsConfigMapByte, &testMap)
//	fmt.Println(testMap)
//	tlsConfigMapStr := base64.StdEncoding.EncodeToString(tlsConfigMapByte)
//	_cache := cache.NewCache(false, 0)
//	_cache.Set(TLS_CONFIG_MAP, tlsConfigMapStr, 10000)
//	return
//}
