package gosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pretty66/gosdk/cienv"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/pretty66/gosdk/errno"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Idn struct {
	AppId   string `json:"appId"`
	AppKey  string `json:"appkey"`
	Channel string `json:"channel"`
	Alias   string `json:"alias"`
	Version string `json:"version"`
}

type kongClient struct {
	header          http.Header
	currentInfo     Idn
	targetInfo      Idn
	proxy           string
	server          Server
	isInit          bool
	timeout         time.Duration // s
	connectTimeout  time.Duration // s
	callStacks      []map[string]string
	subOrgKey       string
	accountId       string
	baseAccountInfo map[string]string
	consumer        string
	secret          []byte
	token           string // 本次请求需要传递过去的token
}

func NewKongClient(header http.Header) (Client, error) {
	client := &kongClient{
		baseAccountInfo: map[string]string{},
		callStacks:      []map[string]string{},
	}

	err = client.initProxy()
	if err != nil {
		return nil, err
	}

	client.timeout = TIMEOUT * time.Second
	client.connectTimeout = CONNECT_TIMEOUT * time.Second

	err = client.ParseTokenInfo(header)
	return client, err
}

// 调用链为空则是app调用
func (c *kongClient) IsCallerApp() bool {
	return len(c.callStacks) == 0
}

func (c *kongClient) initProxy() error {
	if c.proxy == "" {
		c.proxy = cienv.GetEnv(GATEWAY_SERVICE_KEY)
		if c.proxy == "" {
			return errno.GATEWAY_MISSING
		}
		c.proxy = strings.Trim(c.proxy, "\t\n\r /")
		c.proxy = strings.ReplaceAll(c.proxy, "kong:", "")
	}
	return nil
}

func (c *kongClient) ParseTokenInfo(head http.Header) error {
	var err error
	c.server, err = GetServerInstance(head)
	c.header = head
	if err != nil {
		return err
	}
	if c.server.tokenExist {
		/*claims, err := c.server.GetTokenData()
		if err != nil {
			return err
		}*/
		err = c.parseClaims()
		if err != nil {
			return err
		}
		c.isInit = true
	}

	return nil
}

func (c *kongClient) parseClaims() error {
	if c.currentInfo.AppId == "" {
		c.currentInfo.AppId = c.server.GetAppId()
	}
	if c.currentInfo.AppKey == "" {
		c.currentInfo.AppKey = c.server.GetAppKey()
	}
	if c.currentInfo.Channel == "" {
		c.currentInfo.Channel = c.server.GetChannel()
	}

	if c.currentInfo.AppId == "" || c.currentInfo.AppKey == "" || c.currentInfo.Channel == "" {
		return errno.REQUEST_HEADER_ERROR
	}
	c.callStacks = c.server.GetCallStack()
	c.accountId = c.server.GetAccountId()
	c.subOrgKey = c.server.GetSubOrgKey()
	c.baseAccountInfo = c.server.GetUserInfo()
	return nil
}

func (c *kongClient) SetProxy(proxy string) error {
	c.proxy = strings.TrimRight(proxy, "\\ /")
	return nil
}

func (c *kongClient) SetAccountId(accountId string) error {
	if accountId != "" {
		c.accountId = accountId
	}
	return nil
}

func (c *kongClient) SetSubOrgKey(subOrgKey string) error {
	if subOrgKey != "" {
		c.subOrgKey = subOrgKey
	}
	return nil
}

func (c *kongClient) generateStackApp(appId, appKey, channel, version string) map[string]string {
	return map[string]string{
		"appid":   appId,
		"appkey":  appKey,
		"channel": channel,
		"alias":   "",
		"version": version,
	}
}

func (c *kongClient) SetAppInfo(appId, appKey, channel, version string) error {
	if !c.IsCallerApp() {
		return errno.CAN_NOT_CALL_THIS_METHOD
	}
	if appId == "" || appKey == "" || channel == "" {
		return errno.REQUEST_SETING_ERROR
	}
	c.currentInfo.AppId = appId
	c.currentInfo.AppKey = appKey
	c.currentInfo.Channel = channel
	c.callStacks = []map[string]string{}
	c.callStacks = append(c.callStacks, c.generateStackApp(appId, appKey, channel, version))
	c.isInit = true
	return nil
}

func (c *kongClient) SetService(proxyUrl string) *kongClient {
	if proxyUrl != "" {
		c.proxy = proxyUrl
	}
	return c
}

func (client *kongClient) SetUserInfo(userInfo map[string]string) error {
	if !client.IsCallerApp() {
		return errno.CAN_NOT_CALL_THIS_METHOD
	}
	if userInfo["name"] != "" {
		client.baseAccountInfo["name"] = userInfo["name"]
	}
	if userInfo["avatar"] != "" {
		client.baseAccountInfo["avatar"] = userInfo["avatar"]
	}
	return nil
}

func (client *kongClient) SetTimeout(timeout time.Duration) error {
	client.timeout = timeout
	if _httpClient != nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   client.connectTimeout,
			ResponseHeaderTimeout: client.timeout,
		}
		_httpClient.Transport = tr
	}
	return nil
}

func (client *kongClient) SetConnectTimeout(timeout time.Duration) error {
	client.connectTimeout = timeout
	if _httpClient != nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   client.connectTimeout,
			ResponseHeaderTimeout: client.timeout,
		}
		_httpClient.Transport = tr
	}
	return nil
}

func (c *kongClient) makeConsumer() {
	c.consumer = MakeConsumer(c.currentInfo.AppId, c.currentInfo.AppKey, c.currentInfo.Channel)
	// todo secret
	c.secret = []byte(MakeSecret(c.currentInfo.AppId, c.currentInfo.AppKey, c.currentInfo.Channel))
}

func (c *kongClient) makeUrl(serviceName, targetChannelAlias, api string) string {
	targetChannelAlias = strings.Trim(targetChannelAlias, "\\ /")
	api = strings.Trim(api, "\\ /")
	route := MakeRoute(c.currentInfo.AppKey, c.currentInfo.Channel, serviceName, targetChannelAlias)
	c.targetInfo.AppId = serviceName
	c.targetInfo.Alias = targetChannelAlias
	return c.proxy + "/" + route + "/" + api
}

func (c *kongClient) makeUrlForInstance(targetAppId, targetAppKey, targetChannel, api string) string {
	api = strings.Trim(api, "\\ /")
	route := MakeInstanceRoute(c.currentInfo.AppId, c.currentInfo.AppKey, c.currentInfo.Channel, targetAppId, targetAppKey, targetChannel)
	c.targetInfo.AppId = targetAppId
	c.targetInfo.AppKey = targetAppKey
	c.targetInfo.Channel = targetChannel
	return c.proxy + "/" + route + "/" + api
}

func (c *kongClient) getSigner() *jwt.SigningMethodHMAC {
	return jwt.SigningMethodHS256
}

// 组合token数据
func (c *kongClient) claimsForThisRequest() MyClaimsForRequest {
	return MyClaimsForRequest{
		FromAppid:   c.currentInfo.AppId,
		FromAppkey:  c.currentInfo.AppKey,
		FromChannel: c.currentInfo.Channel,
		Alias:       c.targetInfo.Alias,
		AccountId:   c.accountId,
		SubOrgKey:   c.subOrgKey,
		UserInfo:    c.baseAccountInfo,
		CallStack: append(c.callStacks, map[string]string{
			"appid":   c.targetInfo.AppId,
			"appkey":  c.targetInfo.AppKey,
			"channel": c.targetInfo.Channel,
			"alias":   c.targetInfo.Alias,
		}),
	}
}

func (c *kongClient) MakeToken(claims MyClaimsForRequest, expire int64) string {
	now := time.Now().Unix()
	if c.consumer == "" {
		c.makeConsumer()
	}
	claims.ExpiresAt = time.Now().Unix() + expire
	claims.Issuer = c.consumer
	claims.IssuedAt = now
	claims.NotBefore = now
	token := jwt.NewWithClaims(c.getSigner(), claims)
	result, _ := token.SignedString(c.secret)
	return result
}

// 生成一个指定时间过期的token
func (c *kongClient) ReInitCurrentTokenWithSeconds(seconds int64) string {
	claims := MyClaimsForRequest{
		Appid:     c.currentInfo.AppId,
		Appkey:    c.currentInfo.AppKey,
		Channel:   c.currentInfo.Channel,
		SubOrgKey: c.subOrgKey,
		CallStack: c.callStacks,
	}
	return c.MakeToken(claims, seconds)
}

func (c *kongClient) checkParam(method, contentType string) error {
	method = strings.ToLower(method)
	if !In_array(method, ALLOW_METHODS) {
		return errno.METHOD_NOT_ALLOWED
	}

	if !In_array(contentType, []string{CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_MULTIPART}) {
		return errno.CONTENT_TYPE_ERROR
	}
	return nil
}

// todo 后续做成连接池并保持和网关长连接
var _httpClient *http.Client

func (c *kongClient) getHttpClient() *http.Client {
	if _httpClient == nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   c.connectTimeout,
			ResponseHeaderTimeout: c.timeout,
		}
		_httpClient = &http.Client{
			Transport: tr,
		}

		// 解决 80端口重定向到443后 鉴权信息被清除
		_httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if c.header.Get("Authorization") != "" {
				req.Header.Set("Authorization", c.header.Get("Authorization"))
			}
			return nil
		}
	}
	return _httpClient
}

func (c *kongClient) parseBody(
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

func (c *kongClient) Exec(
	method,
	reqUrl string,
	data map[string]interface{},
	contentType string,
	file *fileStruct,
) (out []byte, err error) {

	tlsConfig, err := GetClientTlsConfigByIdns(c.currentInfo, c.targetInfo)
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
			return out, errno.INVALID_HANDSHAKE_STATE_ERROR.Add("Current State -> " + strconv.Itoa(tlsConfig.HandshakeState.currentState()))
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
	req, err := c.parseBody(method, reqUrl, data, contentType, file)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", USER_AGENT+"/"+VERSION)
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	realIp := c.server.GetHeader("x-real-ip")
	if realIp != "" {
		req.Header.Set("x-real-ip", realIp)
	}
	traceid := c.server.GetHeader("x-b3-traceid")
	sampled := c.server.GetHeader("x-b3-sampled")
	if traceid != "" && sampled == "1" {
		req.Header.Set("x-b3-traceid", traceid)
		req.Header.Set("x-b3-sampled", sampled)
	}

	resp, err := c.getHttpClient().Do(req)
	if err != nil {
		err = errno.REQUEST_SETING_ERROR.Add(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		out, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			err = errno.RESPONSE_OTHER.Add(err.Error())
		}
	} else {
		err = requestError(resp)
	}
	return
}

func (c *kongClient) Call(
	serviceName,
	method,
	api string,
	data map[string]interface{},
	channelAlias,
	contentType string,
	file *fileStruct,
) (out []byte, err error) {
	if !c.isInit {
		err = errno.SDK_NOT_INITED
		return
	}
	err = c.checkParam(method, contentType)
	if err != nil {
		return
	}
	// 编译请求链接的uri
	reqUrl := c.makeUrl(serviceName, channelAlias, api)
	// 获取token数据
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)

	out, err = c.Exec(method, reqUrl, data, contentType, file)
	return
}

func (client *kongClient) UploadFile(
	appId string,
	api string,
	files *fileStruct,
	data map[string]interface{},
	channelAlias string) ([]byte, error) {
	return client.Call(appId, "POST", api, data, channelAlias, CONTENT_TYPE_MULTIPART, files)
}

func (c *kongClient) CallByChain(
	chains []map[string]string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	files *fileStruct,
) (out []byte, err error) {
	// chain 之前需要初始化，setAppInfo
	if !c.isInit {
		err = errno.SDK_NOT_INITED
		return
	}
	if len(chains) < 2 {
		err = errno.INVALID_PARAM.Add("Invalid chains input")
		return
	}
	if chains[0]["appid"] != c.callStacks[0]["appid"] || chains[0]["appkey"] != c.callStacks[0]["appkey"] || chains[0]["channel"] != c.callStacks[0]["channel"] {
		err = errno.CHAIN_INVALID
		return
	}
	chainData := FormatChains(chains)
	targetAppId := chainData[len(chainData)-1].Appid
	targetChannelAlias := MakeChains(chainData)
	// 验证是否第一次调用，去注册中心注册调用关系
	/*err = c.checkIsFirstRequest(chainData, targetChannelAlias)
	if err != nil {
		return
	}*/
	// 请求链接
	api = c.makeUrl(targetAppId, targetChannelAlias, api)
	// token中只有自身和目标服务
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)
	out, err = c.Exec(method, api, data, contentType, files)
	return
}

func (c *kongClient) checkIsFirstRequest(chains []chain, hashStr string) error {
	if _cache.Get(hashStr) != "" {
		return nil
	}
	path := os.TempDir() + "/data"
	file := "sdk-cache.json"
	if !IsFileExist(path) {
		err := os.Mkdir(path, 0777)
		if err != nil {
			return errno.SDK_ERROR.Add(err.Error())
		}
	}
	path = path + "/" + file
	cacheData := map[string]string{}
	if IsFileExist(path) {
		cacheContent, err := FileGetContents(path)
		if err != nil {
			return errno.SDK_ERROR.Add(err.Error())
		}
		// json 字符串
		if len(cacheContent) > 0 {
			err = json.Unmarshal(cacheContent, &cacheData)
			if err != nil {
				return errno.SDK_ERROR.Add(err.Error())
			}
			if _, ok := cacheData[hashStr]; ok {
				return nil
			}
		}
	}
	// todo 暂时无法保证map顺序
	data := map[string]interface{}{}
	for k, v := range chains {
		data[fmt.Sprintf("chains[%d][appid]", k)] = v.Appid
		data[fmt.Sprintf("chains[%d][appkey]", k)] = v.Appkey
		data[fmt.Sprintf("chains[%d][channel]", k)] = v.Channel
		if v.Alias != "" {
			data[fmt.Sprintf("chains[%d][alias]", k)] = v.Alias
		}
	}
	// 没有已经缓存的记录则查询注册中心
	api := "main.php/json/deploy/checkHostByChain"
	res, err := c.Call(REGISTER_APPID, "POST", api, data, DEFAULT_CHANNEL_ALIAS, CONTENT_TYPE_FORM, nil)
	if err != nil {
		return errno.SDK_ERROR.Add(err.Error())
	}
	out := map[string]interface{}{}
	err = json.Unmarshal(res, &out)
	if err != nil {
		return errno.JSON_ERROR.Add(err.Error())
	}
	state, ok := out["state"]
	if ok && state.(float64) != 1 {
		return errno.CHAIN_INVALID.Add(out["msg"].(string))
	}
	_cache.Set(hashStr, "1", 0)
	cacheData[hashStr] = "1"
	cacheDataByte, err := json.Marshal(cacheData)
	if err != nil {
		return errno.JSON_ERROR.Add(err.Error())
	}
	FilePutContents(path, cacheDataByte)
	return nil
}

func (c *kongClient) CallServiceInstance(appId,
	appKey,
	channel,
	method,
	api string,
	data map[string]interface{},
	contentType string,
	file *fileStruct) (out []byte, err error) {
	if appId == "" || appKey == "" || channel == "" {
		return nil, errno.INVALID_PARAM.Add("Appid ,appkey can not be null or empty string ,channel can not be null")
	}
	if !c.isInit {
		return nil, errno.INVALID_PARAM.Add("The sdk is not full inited , can not process this request")
	}
	err = c.checkParam(method, contentType)
	if err != nil {
		return
	}
	// 编译请求链接的uri
	reqUrl := c.makeUrlForInstance(appId, appKey, channel, api)
	// 获取token数据
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)

	out, err = c.Exec(method, reqUrl, data, contentType, file)
	return
}

/**
 * 调用setToken 之前先调用 SetCurrentInfo
 */
func (client *kongClient) SetToken(tokenString string) error {
	if tokenString == "" {
		return nil
	}
	if client.currentInfo.AppId == "" || client.currentInfo.AppKey == "" {
		return errno.SDK_NOT_INITED.Add("Should set current info by call setCurrentInfo")
	}

	client.makeConsumer()
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		return token, nil
	})
	tokenIssuer := token.Claims.(jwt.MapClaims)["iss"]
	isTokenIssuer := false
	if tokenIssuer == client.consumer {
		isTokenIssuer = true
	}
	if isTokenIssuer && getSigner().Verify(tokenString, token.Signature, client.secret) == nil {
		/*originClaims := token.Claims.(jwt.MapClaims)
		claims := make(map[string]interface{})
		for k, v := range originClaims {
			claims[k] = v
		}*/
		err = client.server.SetToken(tokenString)
		if err != nil {
			return err
		}
		err := client.parseClaims()
		if err != nil {
			return err
		}
		client.isInit = true
		return err
	}
	return nil
}

func (c *kongClient) GetServer() Server {
	return c.server
}

//初始化tls配置
func (c *kongClient) initTlsConfig(reqUrl string) (out *TlsConfig, err error) {
	tlsConfig := &TlsConfig{
		SessionId:             "",
		IsClient:              true,
		CurrentInfo:           c.currentInfo,
		TargetInfo:            c.targetInfo,
		RequestUrl:            reqUrl,
		HandshakeState:        nil,
		IsEncryptRequired:     c.ifNeedTls(c.currentInfo, c.targetInfo),
		IsCertRequired:        c.isCertRequired(c.currentInfo, c.targetInfo),
		State:                 TLS_STATE_ACTIVING,
		CipherSuites:          c.getCipherSuites(c.currentInfo, c.targetInfo),
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
	timeOut, KeyTimeOut, isReuse, err := c.getInitInfo(c.currentInfo, c.targetInfo)
	if err != nil {
		return nil, err
	}
	tlsConfig.Timeout = timeOut
	tlsConfig.SymmetricKeyExpiresAt = tlsConfig.SymmetricKeyCreatedAt.Add(KeyTimeOut)
	tlsConfig.IsReuse = isReuse
	cert, certChain, publicKey, err := c.getCert(c.currentInfo, c.targetInfo)
	if err != nil {
		return nil, err
	}
	tlsConfig.Cert = cert
	tlsConfig.CertChain = certChain
	tlsConfig.PublicKey = publicKey
	tlsConfig.HandshakeState = &ClientInitState{}
	return tlsConfig, err
}

func (c *kongClient) startTlsHandshake(tlsConfig *TlsConfig) (err error) {
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

func (c *kongClient) sendHandshake(tlsConfig *TlsConfig, handshake *Handshake) (out *Handshake, err error) {
	//以后换成getClient方法
	//client := http.Client{}
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
	//引入标准sdk里的请求头设置
	request.Header.Set("User-Agent", USER_AGENT+"/"+VERSION)
	request.Header.Set("Accept", "application/json")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	realIp := c.server.GetHeader("x-real-ip")
	if realIp != "" {
		request.Header.Set("x-real-ip", realIp)
	}
	traceid := c.server.GetHeader("x-b3-traceid")
	sampled := c.server.GetHeader("x-b3-sampled")
	if traceid != "" && sampled == "1" {
		request.Header.Set("x-b3-traceid", traceid)
		request.Header.Set("x-b3-sampled", sampled)
	}

	if tlsConfig.SessionId != "" {
		request.Header.Set("Session-Id", tlsConfig.SessionId)
	}
	response, err := c.getHttpClient().Do(request)
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

func (c *kongClient) ifNeedTls(currentInfo Idn, targetInfo Idn) bool {
	//if currentInfo.AppKey != targetInfo.AppKey {
	//	return true
	//}
	//if currentInfo.AppKey != "123456" {
	//	return true
	//}
	//return false
	return true
}

func (c *kongClient) isCertRequired(currentInfo Idn, targetInfo Idn) bool {
	//if currentInfo.AppKey != targetInfo.AppKey {
	//	return true
	//}
	if currentInfo.AppKey != "123456" {
		return true
	}
	return false
}

func (c *kongClient) getInitInfo(currentInfo Idn, targetInfo Idn) (timeOut time.Duration, keyTimeOut time.Duration, isReuse bool, err error) {
	return TIMEOUT * time.Second, KEY_TIME_OUT * time.Hour, true, nil
}
func (c *kongClient) getCert(currentInfo Idn, targetInfo Idn) (outCert []byte, outCertChain []byte, outPublicKey []byte, err error) {
	return nil, nil, nil, nil
}

func (c *kongClient) getCipherSuites(currentInfo Idn, targetInfo Idn) (out []int) {
	out = append(out, cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"])
	out = append(out, cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"])
	return
}

var _clientTlsConfigMap map[string]TlsConfig

func GetClientTlsConfigMap() map[string]TlsConfig {
	if _clientTlsConfigMap == nil {
		_clientTlsConfigMap = map[string]TlsConfig{}
	}
	return _clientTlsConfigMap
}
func GetClientTlsConfigByIdns(currentInfo Idn, targetInfo Idn) (tlsConfig *TlsConfig, err error) {
	tlsConfigMap := GetClientTlsConfigMap()
	for _, v := range tlsConfigMap {
		//if currentInfo.AppKey == v.CurrentInfo.AppKey && currentInfo.Channel == v.CurrentInfo.Channel && targetInfo.AppKey == v.TargetInfo.AppKey && targetInfo.Channel == v.TargetInfo.Channel {
		if currentInfo.AppId == v.CurrentInfo.AppId && targetInfo.AppId == v.TargetInfo.AppId {
			return &v, nil
		}
	}
	return nil, nil
}

func SaveClientTlsConfig(tlsConfig *TlsConfig) error {
	tlsConfigMap := GetClientTlsConfigMap()
	tlsConfigMap[tlsConfig.SessionId] = *tlsConfig
	return nil
}
