package utls

type ClientHelloMessage struct {
}

type ServerHelloMessage struct {
}

func (c *Conn) onClientHelloMessage(hello *clientHelloMsg) error {
	// clone client hello message

	if c.config.OnClientHelloMessage == nil {
		return nil
	}
	return c.config.OnClientHelloMessage()
}

func (c *Conn) onServerHelloMessage(hello *serverHelloMsg) error {
	// clone server hello message

	if c.config.OnServerHelloMessage == nil {
		return nil
	}
	return c.config.OnServerHelloMessage()
}
