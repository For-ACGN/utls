// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"slices"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

type ClientHelloBuildStatus int

const NotBuilt ClientHelloBuildStatus = 0
const BuildByUtls ClientHelloBuildStatus = 1
const BuildByGoTLS ClientHelloBuildStatus = 2

type UConn struct {
	*Conn

	Extensions        []TLSExtension
	ClientHelloID     ClientHelloID
	sessionController *sessionController

	clientHelloBuildStatus ClientHelloBuildStatus
	clientHelloSpec        *ClientHelloSpec

	HandshakeState PubClientHandshakeState

	greaseSeed [ssl_grease_last_index]uint16

	omitSNIExtension bool

	// skipResumptionOnNilExtension is copied from `Config.PreferSkipResumptionOnNilExtension`.
	//
	// By default, if ClientHelloSpec is predefined or utls-generated (as opposed to HelloCustom), this flag will be updated to true.
	skipResumptionOnNilExtension bool

	// certCompressionAlgs represents the set of advertised certificate compression
	// algorithms, as specified in the ClientHello. This is only relevant client-side, for the
	// server certificate. All other forms of certificate compression are unsupported.
	certCompressionAlgs []CertCompressionAlgo

	// ech extension is a shortcut to the ECH extension in the Extensions slice if there is one.
	ech ECHExtension

	// echCtx is the echContex returned by makeClientHello()
	echCtx *echClientContext
}

// UClient returns a new uTLS client, with behavior depending on clientHelloID.
// Config CAN be nil, but make sure to eventually specify ServerName.
func UClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) *UConn {
	if config == nil {
		config = &Config{}
	}
	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := PubClientHandshakeState{C: &tlsConn, Hello: &PubClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, ClientHelloID: clientHelloID, HandshakeState: handshakeState}
	uconn.HandshakeState.uconn = &uconn
	uconn.handshakeFn = uconn.clientHandshake
	uconn.sessionController = newSessionController(&uconn)
	uconn.utls.sessionController = uconn.sessionController
	uconn.skipResumptionOnNilExtension = config.PreferSkipResumptionOnNilExtension || clientHelloID.Client != helloCustom
	return &uconn
}

// BuildHandshakeState behavior varies based on ClientHelloID and
// whether it was already called before.
// If HelloGolang:
//
//	[only once] make default ClientHello and overwrite existing state
//
// If any other mimicking ClientHelloID is used:
//
//	[only once] make ClientHello based on ID and overwrite existing state
//	[each call] apply uconn.Extensions config to internal crypto/tls structures
//	[each call] marshal ClientHello.
//
// BuildHandshakeState is automatically called before uTLS performs handshake,
// and should only be called explicitly to inspect/change fields of
// default/mimicked ClientHello.
// With the excpetion of session ticket and psk extensions, which cannot be changed
// after calling BuildHandshakeState, all other fields can be modified.
func (uc *UConn) BuildHandshakeState() error {
	return uc.buildHandshakeState(true)
}

// BuildHandshakeStateWithoutSession is the same as BuildHandshakeState, but does not
// set the session. This is only useful when you want to inspect the ClientHello before
// setting the session manually through SetSessionTicketExtension or SetPSKExtension.
// BuildHandshakeState is automatically called before uTLS performs handshake.
func (uc *UConn) BuildHandshakeStateWithoutSession() error {
	return uc.buildHandshakeState(false)
}

func (uc *UConn) buildHandshakeState(loadSession bool) error {
	if uc.ClientHelloID == HelloGolang {
		if uc.clientHelloBuildStatus == BuildByGoTLS {
			return nil
		}
		uAssert(uc.clientHelloBuildStatus == NotBuilt, "BuildHandshakeState failed: invalid call, client hello has already been built by utls")

		// use default Golang ClientHello.
		hello, keySharePrivate, ech, err := uc.makeClientHello()
		if err != nil {
			return err
		}

		uc.HandshakeState.Hello = hello.getPublicPtr()
		uc.HandshakeState.State13.KeyShareKeys = keySharePrivate.ToPublic()
		uc.HandshakeState.C = uc.Conn
		uc.echCtx = ech
		uc.clientHelloBuildStatus = BuildByGoTLS
	} else {
		uAssert(uc.clientHelloBuildStatus == BuildByUtls || uc.clientHelloBuildStatus == NotBuilt, "BuildHandshakeState failed: invalid call, client hello has already been built by go-tls")
		if uc.clientHelloBuildStatus == NotBuilt {
			err := uc.applyPresetByID(uc.ClientHelloID)
			if err != nil {
				return err
			}
			if uc.omitSNIExtension {
				uc.removeSNIExtension()
			}
		}

		err := uc.ApplyConfig()
		if err != nil {
			return err
		}

		if loadSession {
			err = uc.uLoadSession()
			if err != nil {
				return err
			}
		}

		err = uc.MarshalClientHello()
		if err != nil {
			return err
		}

		if loadSession {
			uc.uApplyPatch()
			uc.sessionController.finalCheck()
			uc.clientHelloBuildStatus = BuildByUtls
		}

	}
	return nil
}

func (uc *UConn) uLoadSession() error {
	if cfg := uc.config; cfg.SessionTicketsDisabled || cfg.ClientSessionCache == nil {
		return nil
	}
	switch uc.sessionController.shouldLoadSession() {
	case shouldReturn:
	case shouldSetTicket:
		uc.sessionController.setSessionTicketToUConn()
	case shouldSetPsk:
		uc.sessionController.setPskToUConn()
	case shouldLoad:
		hello := uc.HandshakeState.Hello.getPrivatePtr()
		uc.sessionController.utlsAboutToLoadSession()
		session, earlySecret, binderKey, err := uc.loadSession(hello)
		if session == nil || err != nil {
			return err
		}
		if session.version == VersionTLS12 {
			// We use the session ticket extension for tls 1.2 session resumption
			uc.sessionController.initSessionTicketExt(session, hello.sessionTicket)
			uc.sessionController.setSessionTicketToUConn()
		} else {
			uc.sessionController.initPskExt(session, earlySecret, binderKey, hello.pskIdentities)
		}
	}

	return nil
}

func (uc *UConn) uApplyPatch() {
	helloLen := len(uc.HandshakeState.Hello.Raw)
	if uc.sessionController.shouldUpdateBinders() {
		uc.sessionController.updateBinders()
		uc.sessionController.setPskToUConn()
	}
	uAssert(helloLen == len(uc.HandshakeState.Hello.Raw), "tls: uApplyPatch Failed: the patch should never change the length of the marshaled clientHello")
}

func (uc *UConn) DidTls12Resume() bool {
	return uc.didResume
}

// SetSessionState sets the session ticket, which may be preshared or fake.
// If session is nil, the body of session ticket extension will be unset,
// but the extension itself still MAY be present for mimicking purposes.
// Session tickets to be reused - use same cache on following connections.
//
// Deprecated: This method is deprecated in favor of SetSessionTicketExtension,
// as it only handles session override of TLS 1.2
func (uc *UConn) SetSessionState(session *ClientSessionState) error {
	sessionTicketExt := &SessionTicketExtension{Initialized: true}
	if session != nil {
		sessionTicketExt.Ticket = session.session.ticket
		sessionTicketExt.Session = session.session
	}
	return uc.SetSessionTicketExtension(sessionTicketExt)
}

// SetSessionTicket sets the session ticket extension.
// If extension is nil, this will be a no-op.
func (uc *UConn) SetSessionTicketExtension(sessionTicketExt ISessionTicketExtension) error {
	if uc.config.SessionTicketsDisabled || uc.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetSessionTicketExtension failed: session is disabled")
	}
	if sessionTicketExt == nil {
		return nil
	}
	return uc.sessionController.overrideSessionTicketExt(sessionTicketExt)
}

// SetPskExtension sets the psk extension for tls 1.3 resumption. This is a no-op if the psk is nil.
func (uc *UConn) SetPskExtension(pskExt PreSharedKeyExtension) error {
	if uc.config.SessionTicketsDisabled || uc.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetPskExtension failed: session is disabled")
	}
	if pskExt == nil {
		return nil
	}

	uc.HandshakeState.Hello.TicketSupported = true
	return uc.sessionController.overridePskExt(pskExt)
}

// If you want session tickets to be reused - use same cache on following connections
func (uc *UConn) SetSessionCache(cache ClientSessionCache) {
	uc.config.ClientSessionCache = cache
	uc.HandshakeState.Hello.TicketSupported = true
}

// SetClientRandom sets client random explicitly.
// BuildHandshakeFirst() must be called before SetClientRandom.
// r must to be 32 bytes long.
func (uc *UConn) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("Incorrect client random length! Expected: 32, got: " + strconv.Itoa(len(r)))
	} else {
		uc.HandshakeState.Hello.Random = make([]byte, 32)
		copy(uc.HandshakeState.Hello.Random, r)
		return nil
	}
}

func (uc *UConn) SetSNI(sni string) {
	hname := hostnameInSNI(sni)
	uc.config.ServerName = hname
	for _, ext := range uc.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
}

// RemoveSNIExtension removes SNI from the list of extensions sent in ClientHello
// It returns an error when used with HelloGolang ClientHelloID
func (uc *UConn) RemoveSNIExtension() error {
	if uc.ClientHelloID == HelloGolang {
		return fmt.Errorf("cannot call RemoveSNIExtension on a UConn with a HelloGolang ClientHelloID")
	}
	uc.omitSNIExtension = true
	return nil
}

func (uc *UConn) removeSNIExtension() {
	filteredExts := make([]TLSExtension, 0, len(uc.Extensions))
	for _, e := range uc.Extensions {
		if _, ok := e.(*SNIExtension); !ok {
			filteredExts = append(filteredExts, e)
		}
	}
	uc.Extensions = filteredExts
}

// Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (uc *UConn) Handshake() error {
	return uc.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
func (uc *UConn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return uc.handshakeContext(ctx)
}

func (uc *UConn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if uc.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	// Start the "interrupter" goroutine, if this context might be canceled.
	// (The background context cannot).
	//
	// The interrupter goroutine waits for the input context to be done and
	// closes the connection if this happens before the function returns.
	if uc.quic != nil {
		uc.quic.cancelc = handshakeCtx.Done()
		uc.quic.cancel = cancel
	} else if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = uc.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	uc.handshakeMutex.Lock()
	defer uc.handshakeMutex.Unlock()

	if err := uc.handshakeErr; err != nil {
		return err
	}
	if uc.isHandshakeComplete.Load() {
		return nil
	}

	uc.in.Lock()
	defer uc.in.Unlock()

	// [uTLS section begins]
	if uc.isClient {
		err := uc.BuildHandshakeState()
		if err != nil {
			return err
		}
	}
	// [uTLS section ends]
	uc.handshakeErr = uc.handshakeFn(handshakeCtx)
	if uc.handshakeErr == nil {
		uc.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		uc.flush()
	}

	if uc.handshakeErr == nil && !uc.isHandshakeComplete.Load() {
		uc.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if uc.handshakeErr != nil && uc.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	if uc.quic != nil {
		if uc.handshakeErr == nil {
			uc.quicHandshakeComplete()
			// Provide the 1-RTT read secret now that the handshake is complete.
			// The QUIC layer MUST NOT decrypt 1-RTT packets prior to completing
			// the handshake (RFC 9001, Section 5.7).
			uc.quicSetReadSecret(QUICEncryptionLevelApplication, uc.cipherSuite, uc.in.trafficSecret)
		} else {
			var a alert
			uc.out.Lock()
			if !errors.As(uc.out.err, &a) {
				a = alertInternalError
			}
			uc.out.Unlock()
			// Return an error which wraps both the handshake error and
			// any alert error we may have sent, or alertInternalError
			// if we didn't send an alert.
			// Truncate the text of the alert to 0 characters.
			uc.handshakeErr = fmt.Errorf("%w%.0w", uc.handshakeErr, AlertError(a))
		}
		close(uc.quic.blockedc)
		close(uc.quic.signalc)
	}

	return uc.handshakeErr
}

// Copy-pasted from tls.Conn in its entirety. But c.Handshake() is now utls' one, not tls.
// Write writes data to the connection.
func (uc *UConn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := uc.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if uc.activeCall.CompareAndSwap(x, x+2) {
			defer uc.activeCall.Add(-2)
			break
		}
	}

	if err := uc.Handshake(); err != nil {
		return 0, err
	}

	uc.out.Lock()
	defer uc.out.Unlock()

	if err := uc.out.err; err != nil {
		return 0, err
	}

	if !uc.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if uc.closeNotifySent {
		return 0, errShutdown
	}

	// SSL 3.0 and TLS 1.0 are susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && uc.vers <= VersionTLS10 {
		if _, ok := uc.out.cipher.(cipher.BlockMode); ok {
			n, err := uc.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, uc.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := uc.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, uc.out.setErrorLocked(err)
}

func (uc *UConn) ApplyConfig() error {
	for _, ext := range uc.Extensions {
		err := ext.writeToUConn(uc)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uc *UConn) extensionsList() []uint16 {

	outerExts := []uint16{}
	for _, ext := range uc.Extensions {
		buffer := cryptobyte.String(make([]byte, 2000))
		ext.Read(buffer)
		var extension uint16
		buffer.ReadUint16(&extension)
		outerExts = append(outerExts, extension)
	}
	return outerExts
}

func (uc *UConn) computeAndUpdateOuterECHExtension(inner *clientHelloMsg, ech *echClientContext, useKey bool) error {
	// This function is mostly copied from
	// https://github.com/For-ACGN/utls/blob/e430876b1d82fdf582efc57f3992d448e7ab3d8a/ech.go#L408
	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}

	encodedInner, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), uc.extensionsList())
	if err != nil {
		return err
	}

	encryptedLen := len(encodedInner) + 16
	outerECHExt, err := generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		return err
	}

	echExtIdx := slices.IndexFunc(uc.Extensions, func(ext TLSExtension) bool {
		_, ok := ext.(EncryptedClientHelloExtension)
		return ok
	})
	if echExtIdx < 0 {
		return fmt.Errorf("extension satisfying EncryptedClientHelloExtension not present")
	}
	oldExt := uc.Extensions[echExtIdx]

	uc.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	if err := uc.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	serializedOuter := uc.HandshakeState.Hello.Raw
	serializedOuter = serializedOuter[4:]
	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		return err
	}
	outerECHExt, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		return err
	}
	uc.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	if err := uc.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	uc.Extensions[echExtIdx] = oldExt
	return nil

}

func (uc *UConn) MarshalClientHello() error {
	if len(uc.config.EncryptedClientHelloConfigList) > 0 {
		inner, _, ech, err := uc.makeClientHello()
		if err != nil {
			return err
		}

		// copy compressed extensions to the ClientHelloInner
		inner.keyShares = KeyShares(uc.HandshakeState.Hello.KeyShares).ToPrivate()
		inner.supportedSignatureAlgorithms = uc.HandshakeState.Hello.SupportedSignatureAlgorithms
		inner.sessionId = uc.HandshakeState.Hello.SessionId
		inner.supportedCurves = uc.HandshakeState.Hello.SupportedCurves

		ech.innerHello = inner

		uc.computeAndUpdateOuterECHExtension(inner, ech, true)

		uc.echCtx = ech
		return nil
	}

	if err := uc.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	return nil

}

// MarshalClientHelloNoECH marshals ClientHello as if there was no
// ECH extension present.
func (uc *UConn) MarshalClientHelloNoECH() error {
	hello := uc.HandshakeState.Hello
	headerLength := 2 + 32 + 1 + len(hello.SessionId) +
		2 + len(hello.CipherSuites)*2 +
		1 + len(hello.CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension // reference to padding extension, if present
	for _, ext := range uc.Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			// If not padding - just add length of extension to total length
			extensionsLen += ext.Len()
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("multiple padding extensions")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uc.Extensions) > 0 {
		helloLen += 2 + extensionsLen // 2 bytes for extensions' length
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4) // 1 byte for tls record type, 3 for length
	// We use buffered Writer to avoid checking write errors after every Write(): whenever first error happens
	// Write() will become noop, and error will be accessible via Flush(), which is called once in the end

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)} // poor man's uint24
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello.Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello.Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello.CipherSuites)<<1))
	for _, suite := range hello.CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.CompressionMethods)

	if len(uc.Extensions) > 0 {
		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uc.Extensions {
			if _, err := bufferedWriter.ReadFrom(ext); err != nil {
				return err
			}
		}
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("utls: unexpected ClientHello length. Expected: " + strconv.Itoa(4+helloLen) +
			". Got: " + strconv.Itoa(helloBuffer.Len()))
	}

	hello.Raw = helloBuffer.Bytes()
	return nil
}

// get current state of cipher and encrypt zeros to get keystream
func (uc *UConn) GetOutKeystream(length int) ([]byte, error) {
	zeros := make([]byte, length)

	if outCipher, ok := uc.out.cipher.(cipher.AEAD); ok {
		// AEAD.Seal() does not mutate internal state, other ciphers might
		return outCipher.Seal(nil, uc.out.seq[:], zeros, nil), nil
	}
	return nil, errors.New("could not convert OutCipher to cipher.AEAD")
}

// SetTLSVers sets min and max TLS version in all appropriate places.
// Function will use first non-zero version parsed in following order:
//  1. Provided minTLSVers, maxTLSVers
//  2. specExtensions may have SupportedVersionsExtension
//  3. [default] min = TLS 1.0, max = TLS 1.2
//
// Error is only returned if things are in clearly undesirable state
// to help user fix them.
func (uc *UConn) SetTLSVers(minTLSVers, maxTLSVers uint16, specExtensions []TLSExtension) error {
	if minTLSVers == 0 && maxTLSVers == 0 {
		// if version is not set explicitly in the ClientHelloSpec, check the SupportedVersions extension
		supportedVersionsExtensionsPresent := 0
		for _, e := range specExtensions {
			switch ext := e.(type) {
			case *SupportedVersionsExtension:
				findVersionsInSupportedVersionsExtensions := func(versions []uint16) (uint16, uint16) {
					// returns (minVers, maxVers)
					minVers := uint16(0)
					maxVers := uint16(0)
					for _, vers := range versions {
						if isGREASEUint16(vers) {
							continue
						}
						if maxVers < vers || maxVers == 0 {
							maxVers = vers
						}
						if minVers > vers || minVers == 0 {
							minVers = vers
						}
					}
					return minVers, maxVers
				}

				supportedVersionsExtensionsPresent += 1
				minTLSVers, maxTLSVers = findVersionsInSupportedVersionsExtensions(ext.Versions)
				if minTLSVers == 0 && maxTLSVers == 0 {
					return fmt.Errorf("SupportedVersions extension has invalid Versions field")
				} // else: proceed
			}
		}
		switch supportedVersionsExtensionsPresent {
		case 0:
			// if mandatory for TLS 1.3 extension is not present, just default to 1.2
			minTLSVers = VersionTLS10
			maxTLSVers = VersionTLS12
		case 1:
		default:
			return fmt.Errorf("uconn.Extensions contains %v separate SupportedVersions extensions",
				supportedVersionsExtensionsPresent)
		}
	}

	if minTLSVers < VersionTLS10 || minTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as min version", minTLSVers)
	}

	if maxTLSVers < VersionTLS10 || maxTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as max version", maxTLSVers)
	}

	uc.HandshakeState.Hello.SupportedVersions = makeSupportedVersions(minTLSVers, maxTLSVers)
	if uc.config.EncryptedClientHelloConfigList == nil {
		uc.config.MinVersion = minTLSVers
		uc.config.MaxVersion = maxTLSVers
	}

	return nil
}

func (uc *UConn) SetUnderlyingConn(c net.Conn) {
	uc.Conn.conn = c
}

func (uc *UConn) GetUnderlyingConn() net.Conn {
	return uc.Conn.conn
}

// MakeConnWithCompleteHandshake allows to forge both server and client side TLS connections.
// Major Hack Alert.
func MakeConnWithCompleteHandshake(tcpConn net.Conn, version uint16, cipherSuite uint16, masterSecret []byte, clientRandom []byte, serverRandom []byte, isClient bool) *Conn {
	tlsConn := &Conn{conn: tcpConn, config: &Config{}, isClient: isClient}
	cs := cipherSuiteByID(cipherSuite)
	if cs != nil {
		// This is mostly borrowed from establishKeys()
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(version, cs, masterSecret, clientRandom, serverRandom,
				cs.macLen, cs.keyLen, cs.ivLen)

		var clientCipher, serverCipher interface{}
		var clientHash, serverHash hash.Hash
		if cs.cipher != nil {
			clientCipher = cs.cipher(clientKey, clientIV, true /* for reading */)
			clientHash = cs.mac(clientMAC)
			serverCipher = cs.cipher(serverKey, serverIV, false /* not for reading */)
			serverHash = cs.mac(serverMAC)
		} else {
			clientCipher = cs.aead(clientKey, clientIV)
			serverCipher = cs.aead(serverKey, serverIV)
		}

		if isClient {
			tlsConn.in.prepareCipherSpec(version, serverCipher, serverHash)
			tlsConn.out.prepareCipherSpec(version, clientCipher, clientHash)
		} else {
			tlsConn.in.prepareCipherSpec(version, clientCipher, clientHash)
			tlsConn.out.prepareCipherSpec(version, serverCipher, serverHash)
		}

		// skip the handshake states
		tlsConn.isHandshakeComplete.Store(true)
		tlsConn.cipherSuite = cipherSuite
		tlsConn.haveVers = true
		tlsConn.vers = version

		// Update to the new cipher specs
		// and consume the finished messages
		tlsConn.in.changeCipherSpec()
		tlsConn.out.changeCipherSpec()

		tlsConn.in.incSeq()
		tlsConn.out.incSeq()

		return tlsConn
	} else {
		// TODO: Support TLS 1.3 Cipher Suites
		return nil
	}
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}

// Extending (*Conn).readHandshake() to support more customized handshake messages.
func (c *Conn) utlsHandshakeMessageType(msgType byte) (handshakeMessage, error) {
	switch msgType {
	case utlsTypeCompressedCertificate:
		return new(utlsCompressedCertificateMsg), nil
	case utlsTypeEncryptedExtensions:
		if c.isClient {
			return new(encryptedExtensionsMsg), nil
		} else {
			return new(utlsClientEncryptedExtensionsMsg), nil
		}
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}
}

// Extending (*Conn).connectionStateLocked()
func (c *Conn) utlsConnectionStateLocked(state *ConnectionState) {
	state.PeerApplicationSettings = c.utls.peerApplicationSettings
}

type utlsConnExtraFields struct {
	// Application Settings (ALPS)
	peerApplicationSettings      []byte
	localApplicationSettings     []byte
	applicationSettingsCodepoint uint16

	sessionController *sessionController
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (uc *UConn) Read(b []byte) (int, error) {
	if err := uc.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	uc.in.Lock()
	defer uc.in.Unlock()

	for uc.input.Len() == 0 {
		if err := uc.readRecord(); err != nil {
			return 0, err
		}
		for uc.hand.Len() > 0 {
			if err := uc.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := uc.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514
	if n != 0 && uc.input.Len() == 0 && uc.rawInput.Len() > 0 &&
		recordType(uc.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := uc.readRecord(); err != nil {
			return n, err // will be io.EOF on closeNotify
		}
	}

	return n, nil
}

// handleRenegotiation processes a HelloRequest handshake message.
func (uc *UConn) handleRenegotiation() error {
	if uc.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := uc.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		uc.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !uc.isClient {
		return uc.sendAlert(alertNoRenegotiation)
	}

	switch uc.config.Renegotiation {
	case RenegotiateNever:
		return uc.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if uc.handshakes > 1 {
			return uc.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		uc.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	uc.handshakeMutex.Lock()
	defer uc.handshakeMutex.Unlock()

	uc.isHandshakeComplete.Store(false)

	// [uTLS section begins]
	if err = uc.BuildHandshakeState(); err != nil {
		return err
	}
	// [uTLS section ends]
	if uc.handshakeErr = uc.clientHandshake(context.Background()); uc.handshakeErr == nil {
		uc.handshakes++
	}
	return uc.handshakeErr
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (uc *UConn) handlePostHandshakeMessage() error {
	if uc.vers != VersionTLS13 {
		return uc.handleRenegotiation()
	}

	msg, err := uc.readHandshake(nil)
	if err != nil {
		return err
	}
	uc.retryCount++
	if uc.retryCount > maxUselessRecords {
		uc.sendAlert(alertUnexpectedMessage)
		return uc.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return uc.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return uc.handleKeyUpdate(msg)
	}
	// The QUIC layer is supposed to treat an unexpected post-handshake CertificateRequest
	// as a QUIC-level PROTOCOL_VIOLATION error (RFC 9001, Section 4.4). Returning an
	// unexpected_message alert here doesn't provide it with enough information to distinguish
	// this condition from other unexpected messages. This is probably fine.
	uc.sendAlert(alertUnexpectedMessage)
	return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
}
