package gosdk

import (
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"testing"
)

func TestStateMachine(t *testing.T) {
	cs := &CipherSuite{}
	cs_rsa := cipherSuites.NewRSA_AES_CBC_SHA256Model()

	fmt.Println(cs)
	fmt.Println(cs_rsa)
	cs.CipherSuiteInterface = cs_rsa
	fmt.Println(cs.CipherSuiteInterface.CipherSuiteKey())
	//cs.cipherSuiteInterface = cs_rsa
}

type cat struct {
	name string
	age  int
}

func TestAppend(t *testing.T) {
	c := &cat{
		name: "ss",
		age:  10,
	}
	map1 := map[string]cat{}
	map1["ss"] = *c
	fmt.Println(map1)
	c.name = "sfdjkslfdj"
	fmt.Println(map1)
}
