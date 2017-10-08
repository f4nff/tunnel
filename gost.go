package gost

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-log/log"
)

// Version is the gost version.
const Version = "nginx"

// Debug is a flag that enables the debug log.
var Debug bool

var (
	tinyBufferSize   = 128
	smallBufferSize  = 1 * 1024  // 1KB small buffer
	mediumBufferSize = 8 * 1024  // 8KB medium buffer
	largeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	// KeepAliveTime is the keep alive time period for TCP connection.
	KeepAliveTime = 60 * time.Second
	// DialTimeout is the timeout of dial.
	DialTimeout = 30 * time.Second
	// ReadTimeout is the timeout for reading.
	ReadTimeout = 30 * time.Second
	// WriteTimeout is the timeout for writing.
	WriteTimeout = 60 * time.Second
	// PingTimeout is the timeout for pinging.
	PingTimeout = 30 * time.Second
	// PingRetries is the reties of ping.
	PingRetries = 3
	// default udp node TTL in second for udp port forwarding.
	defaultTTL = 60 * time.Second
)

var (
	// DefaultTLSConfig is a default TLS config for internal use
	DefaultTLSConfig *tls.Config

	// DefaultUserAgent is the default HTTP User-Agent header used by HTTP and websocket
	DefaultUserAgent = ("Pragma: no-cache\r\n" + "Cache-Control: no-cache\r\n" + "Origin: file://\r\n" + "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\r\n" + "Accept-Encoding: gzip, deflate, sdch\r\n" + "Accept-Language: zh-CN,zh;q=0.8\r\n" + "Cookie: _ga=GA1.2.72523198.1502446485\r\n" + "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits" )
)

func init() {
	rawCert, rawKey, err := generateKeyPair()
	if err != nil {
		panic(err)
	}
	cert, err := tls.X509KeyPair(rawCert, rawKey)
	if err != nil {
		panic(err)
	}
	DefaultTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// log.DefaultLogger = &LogLogger{}
}

// SetLogger sets a new logger for internal log system
func SetLogger(logger log.Logger) {
	log.DefaultLogger = logger
}

func generateKeyPair() (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"gost"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}
