package cert

type pemCertLoader struct {
}

func (c *pemCertLoader) getCert() string {
	return ""
}

func (c *pemCertLoader) getCertChain() []string {
	return nil
}
