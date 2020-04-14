package gosdk

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func HelloServer2(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Inside HelloServer handler")
	fmt.Fprintf(w, "Hello,"+req.URL.Path[1:])
}

func TestHelloServer(t *testing.T) {

	http.HandleFunc("/", HelloServer2)
	err := http.ListenAndServe("localhost:8082", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err.Error())
	}

}

func TestHelloClient(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:8082/hello")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

}
