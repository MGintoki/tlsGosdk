package middle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/labstack/echo"
	"github.com/pretty66/gosdk"
	"github.com/pretty66/gosdk/cache"
	"io/ioutil"
	"strings"
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
		if handshakeCode != "" {
			//判断该请求是否需要加密
		}
		switch c.Request().Header.Get("Content-Type") {
		case gosdk.CONTENT_TYPE_JSON:
			b, err := ioutil.ReadAll(c.Request().Body)
			if err != nil {
				return err
			}
			tmpMap := map[string]interface{}{}
			err = json.Unmarshal(b, &tmpMap)
			if err != nil {
				return err
			}
			if c.Request().Header.Get("If-Encrypted") == "true" {
				cs := gosdk.NewCipherSuiteModel(100)
				fmt.Println(tmpMap["data"])
				data := tmpMap["data"]
				ss, err := base64.StdEncoding.DecodeString(data.(string))

				dataByte := ss
				//dataByte := []byte("28c5Oz2uGB5fD6xKWBhz53FL9rzAIJTWT4ojoNXeieLvjd6Kp8rxQymMZmO2GxTjfWhzFVT0jBVPFdd8V59oB4wgx47lM2XM1yJI/1llZ9thjD2KT6a5sSjMmLZukINE+ekRSnzWTYI2qAqxJCTIqftXTTcMQqb13q+1iL7RrTCBr+Pa0EiJN8e1gAF+BedZ5IGKZS04LZXGfurDD4Q/pw==")
				if err != nil {

				}
				keyByte := []byte("0123456789abcdef")
				plainText, err := cs.CipherSuiteInterface.SymmetricKeyDecrypt(dataByte, keyByte)
				if err != nil {

				}
				tmpMap["plainText"] = plainText
			}
			tmpMapByte, err := json.Marshal(tmpMap)
			c.Request().Body = ioutil.NopCloser(strings.NewReader(string(tmpMapByte)))
		}

		return next(c)

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
	_cache := cache.NewCache(false, 0)
	fmt.Println(_cache.Get("testCache"))
	tmpMap := map[string]interface{}{}
	err = json.Unmarshal(b, &tmpMap)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(b))
	return NewOut(c, nil, tmpMap)
}

func LoadMidRoute(e *echo.Echo) {
	e.Use(TestMid)
	e.POST("/test", TestController)
}

func GetIfEncrypt(flag bool) bool {
	return flag
}
