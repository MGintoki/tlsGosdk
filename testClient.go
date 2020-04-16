package gosdk

import (
	"fmt"
	"net/http"
)

type TlsClient struct {
	clientInfo  string
	serverInfo  string
	requestPath string
	tlsConfig   *TlsConfig
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
