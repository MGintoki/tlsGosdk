package gosdk

import "time"

type keypair struct {
	SessionId   string    `json:"sessionId"`
	PrivateKey  []byte    `json:"privateKey"`
	PublicKey   []byte    `json:"publicKey"`
	KeypairType int       `json:"keypairType"`
	CreateAt    time.Time `json:"createAt"`
}
