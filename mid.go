package gosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/labstack/echo"
	"github.com/pretty66/gosdk/errno"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func HandleTLS(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		return next(c)
	}
}

func TestMid(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		handshakeCode := c.Request().Header.Get("Handshake-Code")
		//如果没有handshakeActionCode，则该链接为非加密连接
		//如果handshakeActionCode存在，则发送过来的是一个handshake结构体
		if handshakeCode != "" {
			contentType := c.Request().Header.Get("Content-Type")
			//以后要检测，如果发送的是加密请求，contentType不是json，要有相应的处理
			if contentType != CONTENT_TYPE_JSON {

			}
			handshake := &Handshake{}
			b, err := ioutil.ReadAll(c.Request().Body)
			if err != nil {
				return errno.REQUEST_SETING_ERROR.Add(err.Error())
			}
			err = json.Unmarshal(b, &handshake)
			if err != nil {
				return errno.JSON_ERROR.Add(err.Error())
			}
			fromServer, err := GetServerInstance(c.Request().Header)
			if err != nil {
				return errno.SDK_ERROR.Add(err.Error())
			}
			fmt.Println(fromServer)
			tmpIdn := Idn{
				//AppKey:  fromServer.GetFromAppKey(),
				//Channel: fromServer.GetFromChannel(),
				AppKey:  "1234567",
				Channel: "1234567",
			}
			tlsConfig := GetServerTlsConfigByIdns(tmpIdn)
			if tlsConfig == nil {
				if handshake.ActionCode != CLIENT_HELLO_CODE {
					return errno.INVALID_HANDSHAKE_STATE_ERROR
				}
				reqUrl := c.Request().URL.Path
				tlsConfig, err = initServerTlsConfig(reqUrl, tmpIdn)
			}
			handshakeCodeInt, err := strconv.Atoi(handshakeCode)
			if err != nil {
				return errno.SDK_ERROR.Add(err.Error())
			}
			if handshakeCodeInt == CLIENT_APP_DATA_CODE {
				dataEncryptedStr := handshake.AppData.Data
				dataEncryptedByte, err := base64.StdEncoding.DecodeString(dataEncryptedStr)
				if err != nil {
					return errno.BASE64_DECODE_ERROER.Add(err.Error())
				}
				dataPlainText, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(dataEncryptedByte, tlsConfig.SymmetricKey)
				MACLocal := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateMAC(dataPlainText)
				MACReceivedByte, err := base64.StdEncoding.DecodeString(handshake.AppData.MAC)
				if err != nil {
					return errno.BASE64_DECODE_ERROER.Add(err.Error())
				}
				MACReceived, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(MACReceivedByte, tlsConfig.SymmetricKey)
				if err != nil {
					return errno.JSON_ERROR.Add(err.Error())
				}
				if string(MACLocal) != string(MACReceived) {
					return errno.MAC_VERIFY_ERROR
				}
				SaveServerTlsConfig(tlsConfig)
				switch c.Request().Header.Get("Content-Type") {
				case CONTENT_TYPE_JSON:
					body := bytes.NewReader(dataPlainText)
					c.Request().Body = ioutil.NopCloser(body)
					return next(c)
				case CONTENT_TYPE_FORM:
					data := map[string]interface{}{}
					err := json.Unmarshal(dataPlainText, &data)
					if err != nil {
						return errno.JSON_ERROR.Add(err.Error())
					}
					theData := url.Values{}
					for k, v := range data {
						theData.Set(k, fmt.Sprint(v))
					}
					body := strings.NewReader(theData.Encode())
					c.Request().Body = ioutil.NopCloser(body)

				case CONTENT_TYPE_MULTIPART:
					data := map[string]interface{}{}
					err := json.Unmarshal(dataPlainText, &data)
					if err != nil {
						return errno.JSON_ERROR.Add(err.Error())
					}
					buff := &bytes.Buffer{}
					bodyWriter := multipart.NewWriter(buff)
					// 写入其他参数
					for k, v := range data {
						err := bodyWriter.WriteField(k, fmt.Sprint(v))
						if err != nil {
							return errno.SDK_ERROR.Add(err.Error() + "error in mid multipart parse")
						}
					}
				}

			} else {
				out, err := tlsConfig.HandshakeState.handleAction(tlsConfig, handshake, handshakeCodeInt)
				if err != nil {
					return errno.HANDSHAKE_ERROR.Add(err.Error())
				}
				outByte, err := json.Marshal(out)
				c.Response().Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
				c.Response().Writer.Header().Set("HandShake-Code", strconv.Itoa(out.ActionCode))
				c.Response().Writer.Write(outByte)
				SaveServerTlsConfig(tlsConfig)
				return err
			}
		}
		fmt.Println("sfjlajlsdfla")
		return err

		//fmt.Println(string(reflect.ValueOf(c.Response().Writer).Elem().FieldByName("w").Elem().FieldByName("buf").Bytes()))
		//resBytes := reflect.ValueOf(c.Response().Writer).Elem().FieldByName("w").Elem().FieldByName("buf").Bytes()
		//fmt.Println(resBytes)
		//reflect.ValueOf(c.Response().Writer).Elem().FieldByName("w").Elem().FieldByName("buf").Bytes()

	}
}

func TestController(c echo.Context) error {
	fmt.Println(c.FormValue("test"))
	b, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {

	}
	tmpMap := map[string]interface{}{}
	err = json.Unmarshal(b, &tmpMap)
	if err != nil {
		fmt.Println(err)
	}
	tmpMap["test4"] = "test4"
	tmpMap["test5"] = 5
	//fmt.Println(string(b))
	fmt.Println("---data:------")
	fmt.Println(tmpMap)
	return NewOut(c, nil, tmpMap)
}

func LoadMidRoute(e *echo.Echo) {
	e.Use(TestMid)
	e.POST("/test", TestController)
}

var _serverTlsConfigMap map[string]TlsConfig

func GetServerTlsConfigMap() map[string]TlsConfig {
	if _serverTlsConfigMap == nil {
		_serverTlsConfigMap = map[string]TlsConfig{}
	}
	return _serverTlsConfigMap
}

func GetServerTlsConfigByIdns(currentInfo Idn) (tlsConfig *TlsConfig) {
	tlsConfigMap := GetServerTlsConfigMap()
	for _, v := range tlsConfigMap {
		//if currentInfo.AppKey == v.CurrentInfo.AppKey && currentInfo.Channel == v.CurrentInfo.Channel {
		if currentInfo.AppId == v.CurrentInfo.AppId {

			//需要检测是否过期，过期的话返回nil
			return &v
		}
	}
	return nil
}

func SaveServerTlsConfig(tlsConfig *TlsConfig) {
	tlsConfigMap := GetServerTlsConfigMap()
	tlsConfigMap[tlsConfig.SessionId] = *tlsConfig
}

func NewOut(c echo.Context, err error, data interface{}) error {
	if err != nil {
		return c.JSON(http.StatusOK, err)
	}
	if data == nil {
		data = []string{}
	}
	//fromServer, err := GetServerInstance(c.Request().Header)
	//fromAppkey := fromServer.GetAppKey()
	//fromChanel := fromServer.GetChannel()
	tmpIdn := Idn{
		//AppKey:  fromServer.GetFromAppKey(),
		//Channel: fromServer.GetFromChannel(),
		AppKey:  "1234567",
		Channel: "1234567",
	}
	tlsConfig := GetServerTlsConfigByIdns(tmpIdn)
	if tlsConfig.IsEncryptRequired == true && tlsConfig.HandshakeState.currentState() == SERVER_ENCRYPTED_CONNECTION_STATE {
		dataByte, err := json.Marshal(data)
		if err != nil {
			return errno.JSON_ERROR.Add(err.Error())
		}
		dataEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(dataByte, tlsConfig.SymmetricKey)
		if err != nil {

		}
		dataEncodeStr := base64.StdEncoding.EncodeToString(dataEncrypted)
		MAC := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateMAC(dataByte)
		MACEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(MAC, tlsConfig.SymmetricKey)
		MACEncodeStr := base64.StdEncoding.EncodeToString(MACEncrypted)
		appdata := &AppData{
			Data: dataEncodeStr,
			MAC:  MACEncodeStr,
		}
		handshake := &Handshake{
			Version:       "",
			HandshakeType: 0,
			ActionCode:    SERVER_APP_DATA_CODE,
			SessionId:     tlsConfig.SessionId,
			SendTime:      time.Time{},
			AppData:       appdata,
		}
		handshakeMarshal, err := json.Marshal(handshake)
		if err != nil {
			return errno.JSON_ERROR.Add(err.Error())
		}
		handshakeEncodeStr := base64.StdEncoding.EncodeToString(handshakeMarshal)
		data = handshakeEncodeStr
		c.Response().Header().Set("HandShake-Code", strconv.Itoa(SERVER_APP_DATA_CODE))
	}
	//ss, err := base64.StdEncoding.DecodeString(cipherTest)
	return c.JSON(http.StatusOK, out{
		State: 1,
		Msg:   "success",
		Data:  data,
	})
}

type out struct {
	State int         `json:"state"`
	Msg   string      `json:"msg"`
	Data  interface{} `json:"data"`
}
