package middle

import (
	"encoding/base64"
	"encoding/json"
	"github.com/labstack/echo"
	"github.com/pretty66/gosdk"
	"net/http"
)

func LoadRoute(e *echo.Echo) {
	e.Use(HandleTLS)
	e.POST("/test", Test)
}
func Test(c echo.Context) error {

	name := c.FormValue("name")
	out := map[string]interface{}{}
	out["test1"] = "test1"
	out["tests2"] = 222
	out["test3"] = []string{"test3/test3"}
	out["test4"] = name
	return NewOut(c, nil, out)
}

func NewOut(c echo.Context, err error, data interface{}) error {
	if err != nil {
		return c.JSON(http.StatusOK, err)
	}
	if data == nil {
		data = []string{}
	}
	if GetIfEncrypt(true) {
		cs := gosdk.NewCipherSuiteModel(100)
		dataByte, err := json.Marshal(data)
		if err != nil {

		}
		keyByte := []byte("0123456789abcdef")
		cipherText, err := cs.CipherSuiteInterface.SymmetricKeyEncrypt(dataByte, keyByte)
		if err != nil {

		}

		cipherTest := base64.StdEncoding.EncodeToString(cipherText)
		//ss, err := base64.StdEncoding.DecodeString(cipherTest)
		return c.JSON(http.StatusOK, out{
			State: 1,
			Msg:   "test",
			Data:  cipherTest,
		})

	}
	return c.JSON(http.StatusOK, out{
		State: 1,
		Msg:   "test",
		Data:  data,
	})
}

type out struct {
	State int         `json:"state"`
	Msg   string      `json:"msg"`
	Data  interface{} `json:"data"`
}
