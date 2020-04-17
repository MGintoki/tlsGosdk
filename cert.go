package gosdk

import "time"

type CertLoader interface {
	GetCert() string
	GetCertChain() []string
}

type Cert struct {
	Cert      string    `json:"cert"`
	CertChain string    `json:"certChain"`
	State     string    `json:"state"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

func verifyCert(cert *Cert) (stateCode string) {

	return ""
}
