package gosdk

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"github.com/pretty66/gosdk/errno"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GetIp() string {
	var ip string
	if os.Getenv("SERVER_ADDR") != "" && !strings.EqualFold(os.Getenv("SERVER_ADDR"), "unknown") {
		ip = os.Getenv("SERVER_ADDR")
	}
	if ip == "" {
		ip = "0.0.0.0"
	}
	//7位-15位，由数字和.组成
	regs, _ := regexp.Compile(`[\d.]{7,15}`)
	str := regs.FindAllString(ip, -1)
	if len(str) > 0 {
		return str[0]
	}
	return ""
}

func GetPort(head http.Header) string {
	if head.Get("SERVER_PORT") != "" {
		return head.Get("SERVER_PORT")
	}
	return "0"
}

func Zipkin_timestamp() string {
	localTime := time.Now().UnixNano()
	return strconv.FormatInt(localTime/1000, 10)
}

func NewMd5(str ...string) string {
	h := md5.New()
	for _, v := range str {
		h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewImplodeMd5(glue string, str ...string) string {
	s := strings.Join(str, glue)
	return NewMd5(s)
}

func In_array(s string, slice []string) bool {
	for _, v := range slice {
		if s == v {
			return true
		}
	}
	return false
}

type chain struct {
	Appid   string `json:"appid"`
	Appkey  string `json:"appkey"`
	Channel int    `json:"channel"`
	Alias   string `json:"alias,omitempty"`
}

func FormatChains(chains []map[string]string) []chain {
	chainData := make([]chain, len(chains))
	for k, v := range chains {
		if k == 0 {
			// channel string
			chainData[k] = chain{
				Appid:  v["appid"],
				Appkey: v["appkey"],
			}
			chainData[k].Channel, _ = strconv.Atoi(v["channel"])
		} else {
			var ok bool
			chainData[k] = chain{
				Appid:  v["appid"],
				Appkey: v["appkey"],
			}
			chainData[k].Channel, _ = strconv.Atoi(v["channel"])
			chainData[k].Alias, ok = v["alias"]
			if !ok {
				chainData[k].Alias, ok = v["channelAlias"]
			}
		}
	}
	return chainData
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func FileGetContents(path string) (out []byte, err error) {
	if IsFileExist(path) {
		out, err = ioutil.ReadFile(path)
	}
	return
}

func FilePutContents(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(content)
	if err != nil {
		return err
	}
	return nil
}

func requestError(response *http.Response) error {
	switch response.StatusCode {
	case 401:
		return errno.RESPONSE_401
	case 403:
		return errno.RESPONSE_403
	case 404:
		body, _ := ioutil.ReadAll(response.Body)
		return errno.RESPONSE_404.SetCode(response.StatusCode, string(body))
	default:
		body, _ := ioutil.ReadAll(response.Body)
		return errno.RESPONSE_OTHER.SetCode(response.StatusCode, string(body))
	}
}

func ChangeTypeToString(value interface{}) string {
	var key string
	if value == nil {
		return key
	}
	switch value.(type) {
	case float64:
		ft := value.(float64)
		key = strconv.FormatFloat(ft, 'f', -1, 64)
	case float32:
		ft := value.(float32)
		key = strconv.FormatFloat(float64(ft), 'f', -1, 64)
	case int:
		it := value.(int)
		key = strconv.Itoa(it)
	case uint:
		it := value.(uint)
		key = strconv.Itoa(int(it))
	case int8:
		it := value.(int8)
		key = strconv.Itoa(int(it))
	case uint8:
		it := value.(uint8)
		key = strconv.Itoa(int(it))
	case int16:
		it := value.(int16)
		key = strconv.Itoa(int(it))
	case uint16:
		it := value.(uint16)
		key = strconv.Itoa(int(it))
	case int32:
		it := value.(int32)
		key = strconv.Itoa(int(it))
	case uint32:
		it := value.(uint32)
		key = strconv.Itoa(int(it))
	case int64:
		it := value.(int64)
		key = strconv.FormatInt(it, 10)
	case uint64:
		it := value.(uint64)
		key = strconv.FormatUint(it, 10)
	case string:
		key = value.(string)
	case []byte:
		key = string(value.([]byte))
	default:
		newValue, _ := json.Marshal(value)
		key = string(newValue)
	}

	return key
}
