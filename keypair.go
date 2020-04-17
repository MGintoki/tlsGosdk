package gosdk

import "time"

type keypair struct {
	SessionId   string    `json:"sessionId"`
	PrivateKey  string    `json:"privateKey"`
	PublicKey   string    `json:"publicKey"`
	KeypairType string    `json:"keypairType"`
	CreateAt    time.Time `json:"createAt"`
}
