package gosdk

import "time"

type keypair struct {
	sessionId   string
	privateKey  string
	publicKey   string
	keypairType string
	createAt    time.Time
}
