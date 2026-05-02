package utls

import (
	"crypto/tls"
)

func ToTLSCertificate(cert *Certificate) *tls.Certificate {
	crt := &tls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for i := 0; i < len(cert.SupportedSignatureAlgorithms); i++ {
		scheme := tls.SignatureScheme(cert.SupportedSignatureAlgorithms[i])
		crt.SupportedSignatureAlgorithms[i] = scheme
	}
	return crt
}

func ToUTLSCertificate(cert *tls.Certificate) *Certificate {
	crt := &Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for i := 0; i < len(cert.SupportedSignatureAlgorithms); i++ {
		scheme := SignatureScheme(cert.SupportedSignatureAlgorithms[i])
		crt.SupportedSignatureAlgorithms[i] = scheme
	}
	return crt
}
