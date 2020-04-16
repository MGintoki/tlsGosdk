package cert

type PemCertLoader struct {
}

func (c *PemCertLoader) GetCert() string {
	return ""
}

func (c *PemCertLoader) GetCertChain() []string {
	return nil
}
