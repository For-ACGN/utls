package utls

type ClientHelloMessage struct {
	Random    []byte
	SessionID []byte
	ALPNProto []string
}

type ServerHelloMessage struct {
	Random    []byte
	SessionID []byte
	ALPNProto string
}

func (c *Conn) onClientHelloMessage(hello *clientHelloMsg) error {
	if c.config.OnClientHelloMessage == nil {
		return nil
	}
	// clone client hello message
	msg := &ClientHelloMessage{
		Random:    hello.random,
		SessionID: hello.sessionId,
		ALPNProto: hello.alpnProtocols,
	}
	err := c.config.OnClientHelloMessage(msg)
	if err != nil {
		return err
	}
	// adjust the original hello message
	hello.random = msg.Random
	hello.sessionId = msg.SessionID
	hello.alpnProtocols = msg.ALPNProto
	return nil
}

func (c *Conn) onServerHelloMessage(hello *serverHelloMsg) error {
	if c.config.OnServerHelloMessage == nil {
		return nil
	}
	// clone server hello message
	msg := &ServerHelloMessage{
		Random:    hello.random,
		SessionID: hello.sessionId,
		ALPNProto: hello.alpnProtocol,
	}
	err := c.config.OnServerHelloMessage(msg)
	if err != nil {
		return err
	}
	// adjust the original hello message
	hello.random = msg.Random
	hello.sessionId = msg.SessionID
	hello.alpnProtocol = msg.ALPNProto
	return nil
}
