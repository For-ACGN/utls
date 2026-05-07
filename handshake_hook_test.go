package utls

import (
	"bytes"
	"crypto/x509"
	"net"
	"testing"
)

func TestOnClientHelloMessage(t *testing.T) {
	hook := func(hello *ClientHelloMessage) error {
		secret := make([]byte, 32)
		secret[0] = 0xFF
		if bytes.Equal(hello.Random, secret) {
			hello.ALPNProto = []string{"http/1.1"}
		}
		return nil
	}

	serverCfg := &Config{
		Certificates:         testConfig.Clone().Certificates,
		NextProtos:           []string{"h2", "http/1.1"},
		OnClientHelloMessage: hook,
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	testCheckError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			c := conn.(*Conn)
			err = c.Handshake()
			testCheckError(t, err)

			err = conn.Close()
			testCheckError(t, err)
		}
	}()

	clientCfg := &Config{
		NextProtos:         []string{"h2", "http/1.1"},
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}

	t.Run("Dial", func(t *testing.T) {
		// set secret random data
		clientCfg.Random = make([]byte, 32)
		clientCfg.Random[0] = 0xFF

		conn, err := Dial("tcp", listener.Addr().String(), clientCfg.Clone())
		testCheckError(t, err)

		err = conn.Handshake()
		testCheckError(t, err)
		if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
			t.Fatal("NegotiatedProtocol should be http/1.1")
		}

		err = conn.Close()
		testCheckError(t, err)
	})

	t.Run("UClient", func(t *testing.T) {
		raw, err := net.Dial("tcp", listener.Addr().String())
		testCheckError(t, err)
		conn := UClient(raw, clientCfg.Clone(), HelloFirefox_Auto)

		random := make([]byte, 32)
		random[0] = 0xFF
		err = conn.BuildHandshakeState()
		testCheckError(t, err)
		err = conn.SetClientRandom(random)
		testCheckError(t, err)

		err = conn.Handshake()
		testCheckError(t, err)
		if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
			t.Fatal("NegotiatedProtocol should be http/1.1")
		}

		err = conn.Close()
		testCheckError(t, err)
	})

	err = listener.Close()
	testCheckError(t, err)
}

func TestOnServerHelloMessage(t *testing.T) {
	serverCfg := &Config{
		Certificates: testConfig.Clone().Certificates,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	testCheckError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			c := conn.(*Conn)
			err = c.Handshake()
			testCheckError(t, err)

			err = conn.Close()
			testCheckError(t, err)
		}
	}()

	hook := func(hello *ServerHelloMessage) error {
		t.Log("random:", hello.Random)
		t.Log("session id:", hello.SessionID)
		t.Log("protocol:", hello.ALPNProto)
		return nil
	}
	clientCfg := &Config{
		NextProtos:           []string{"h2", "http/1.1"},
		RootCAs:              x509.NewCertPool(),
		InsecureSkipVerify:   true,
		OnServerHelloMessage: hook,
	}

	t.Run("Dial", func(t *testing.T) {
		conn, err := Dial("tcp", listener.Addr().String(), clientCfg.Clone())
		testCheckError(t, err)

		err = conn.Handshake()
		testCheckError(t, err)
		if conn.ConnectionState().NegotiatedProtocol != "h2" {
			t.Fatal("NegotiatedProtocol should be h2")
		}

		err = conn.Close()
		testCheckError(t, err)
	})

	t.Run("UClient", func(t *testing.T) {
		raw, err := net.Dial("tcp", listener.Addr().String())
		testCheckError(t, err)
		conn := UClient(raw, clientCfg, HelloFirefox_Auto)

		err = conn.Handshake()
		testCheckError(t, err)
		if conn.ConnectionState().NegotiatedProtocol != "h2" {
			t.Fatal("NegotiatedProtocol should be h2")
		}

		err = conn.Close()
		testCheckError(t, err)
	})

	err = listener.Close()
	testCheckError(t, err)
}

func testCheckError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
