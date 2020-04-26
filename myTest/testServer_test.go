package myTest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

func Test_test1(t *testing.T) {

}

const REQUEST_URL = "http://127.0.0.1:8081"
const LISTEN_URL = "localhost:8081"

func helloWorld(w http.ResponseWriter, r *http.Request) {
	//根据请求方法的不同，调用不同的处理方式
	switch r.Method {
	case "GET":
		//遍历get请求的参数（？后跟的那些数值）
		for k, v := range r.URL.Query() {
			fmt.Printf("%s: %s\n", k, v)
		}
		w.Write([]byte("hello world"))
	case "POST":
		reqBodyByte, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", reqBodyByte)
		//设置相应头，指定数据为json格式
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		//自定义相应头
		w.Header().Set("session-id", "sdfafsdafadsf")
		tmpMap := map[string]interface{}{
			"test1": 111,
			"test2": "222",
			"test3": "测试测试测试",
		}
		//写入json数据
		w.Write([]byte(`{"hello":"world"}`))
		tmpMapByte, err := json.Marshal(tmpMap)
		if err != nil {

		}
		w.Write(tmpMapByte)
		w.Write(reqBodyByte)
	default:
	}
}

func handleResponseHandshake(w http.ResponseWriter, r *http.Request) {
	var clientHs Handshake
	err := json.NewDecoder(r.Body).Decode(&clientHs)
	if err != nil {
		fmt.Println("err")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	ch := &ClientHello{
		IsClientEncryptRequired: true,
		IsCertRequired:          false,
	}
	hs := &Handshake{
		Version:       "version",
		HandshakeType: 1,
		SendTime:      time.Time{},
	}
	hs.ClientHello = ch
	hsMarshal, err := json.Marshal(hs)
	if err != nil {
		log.Fatal(err)
	}
	w.Write(hsMarshal)
}
func TestHelloWorldServer(t *testing.T) {
	http.HandleFunc("/helloWorld", helloWorld)
	http.HandleFunc("/handshake", handleResponseHandshake)
	http.ListenAndServe(LISTEN_URL, nil)
}

//测试自定义http client 发送 request
func TestClient(t *testing.T) {
	url := REQUEST_URL + "/"
	client := http.Client{}
	//设置请求超时时间
	//client.Timeout = 1 * time.Second

	//更为精细的控制超时时间
	//tr := &http.Transport{
	//	DialContext: (&net.Dialer{
	//		Timeout:   30 * time.Second,
	//		KeepAlive: 3000 * time.Millisecond,
	//	}).DialContext,
	//	TLSHandshakeTimeout: 10 *time.Second,
	//	IdleConnTimeout: 90 * time.Second,
	//	ResponseHeaderTimeout: 10 * time.Second,
	//	ExpectContinueTimeout: 1 * time.Second,
	//}
	//client := &http.Client{
	//	Transport: tr,
	//}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	response, err := client.Do(request)
	//延迟读写流到执行的最后关闭
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", body)

}

func TestHandshakeRequest(t *testing.T) {
	sendHs := Handshake{
		Version:       "test",
		HandshakeType: 0,
		ActionCode:    0,
		SessionId:     "",
		SendTime:      time.Time{},
		ClientHello:   nil,
	}
	clientHello := &ClientHello{
		IsClientEncryptRequired: false,
		IsCertRequired:          true,
		CipherSuites:            nil,
	}
	sendHs.ClientHello = clientHello
	sendHsByte, err := json.Marshal(sendHs)
	if err != nil {
		fmt.Println(err)
	}
	url := REQUEST_URL + "/handshake"
	client := http.Client{}
	request, err := http.NewRequest("OPTION", url, bytes.NewReader(sendHsByte))
	//request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Type", "application/json")

	if err != nil {
		log.Fatal(err)
	}
	response, err := client.Do(request)
	defer response.Body.Close()
	var hs Handshake
	//var hsMap map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&hs)
	//err = json.NewDecoder(response.Body).Decode(&hsMap)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hs)
	//fmt.Println(hsMap)
}

func TestClientHelloWorldGet(t *testing.T) {
	url := REQUEST_URL + "/helloWorld"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(body)
	}
	fmt.Printf("%s", body)
}

func TestClientHelloWorldPost(t *testing.T) {
	url := REQUEST_URL + "/"
	postData := strings.NewReader(`{"test":"test"}`)
	resp, err := http.Post(url, "application/json", postData)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(body)
	}
	fmt.Printf("%s", body)
}

type Handshake struct {
	Version       string    `json:"version"`
	HandshakeType int       `json:"handshakeType"` //握手类型，是协商还是警告
	ActionCode    int       `json:"actionCode"`
	SessionId     string    `json:"sessionId"`
	SendTime      time.Time `json:"sendTime"` //发送时间

	//初始化HandShake时，根据handshakeCode指定了生成下面具体的消息
	ClientHello *ClientHello `json:"clientHello"`
}

type ClientHello struct {
	IsClientEncryptRequired bool  `json:"isClientEncryptRequired"` //是否需要加密
	IsCertRequired          bool  `json:"isCertRequired"`          //是否需要服务端证书，不需要的话，说明客户端从部署指定路径获取
	CipherSuites            []int `json:"cipherSuites"`
}
type people struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func TestMarshal(t *testing.T) {
	hs := &Handshake{
		Version:       "",
		HandshakeType: 0,
		ActionCode:    0,
		SessionId:     "",
		SendTime:      time.Time{},
		ClientHello:   nil,
	}
	ch := &ClientHello{
		IsClientEncryptRequired: false,
		IsCertRequired:          false,
		CipherSuites:            nil,
	}
	hs.ClientHello = ch
	hsMarshal, err := json.Marshal(hs)
	if err != nil {

	}
	fmt.Printf(string(hsMarshal))
	chMarshal, err := json.Marshal(ch)
	if err != nil {

	}
	fmt.Println(string(chMarshal))
	p := &people{
		Name: "张三",
		Age:  22,
	}
	pMarshal, err := json.Marshal(p)
	fmt.Println(pMarshal)
}
