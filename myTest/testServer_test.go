package myTest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
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
	default:

	}

}

func TestHelloWorldServer(t *testing.T) {
	http.HandleFunc("/helloWorld", helloWorld)
	http.ListenAndServe(LISTEN_URL, nil)
}
