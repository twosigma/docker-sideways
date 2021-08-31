package main

import(
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"fmt"
)

func sendPeerCerts(res http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		res.WriteHeader(404)
		fmt.Fprint(res, "/peer_certs is only available over HTTPS\n")
		return
	}

	var allCerts []map[string]string
	for _, cert := range req.TLS.PeerCertificates {
		c := make(map[string]string)
		c["Serial"] = cert.SerialNumber.String()
		c["Issuer"] = cert.Issuer.String()
		c["Subject"] = cert.Subject.String()
		allCerts = append(allCerts, c)
	}

	j, err := json.MarshalIndent(allCerts, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprint(res, string(j) + "\n")
}

func sendHeaders(res http.ResponseWriter, req *http.Request) {
	h := make(map[string][]string)
	h["Host"] = append(h["Host"], req.Host)
	for k, v := range req.Header {
		h[k] = v
	}

	j, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprint(res, string(j) + "\n")
}

func setupTLS(ca, crt, key string) (*tls.Config, error) {
	caCertPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPEM)
	if !ok {
		panic("failed to parse root certificate")
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    roots,
	}, nil
}

func main() {
	http_addr := flag.String("http_addr", ":8080", "HTTP listen address")
	https_addr := flag.String("https_addr", ":8443", "HTTPS listen address")
	ca := flag.String("ca", "/etc/ssl/certs/ca-certificates.crt", "CA certificates file")
	crt := flag.String("crt", "cert.pem", "Server certificate")
	key := flag.String("key", "key.pem", "Server key")
	flag.Parse()

	tlsconf, err := setupTLS(*ca, *crt, *key)
	if err != nil {
		log.Fatal("setupTLS: %s", err.Error())
	}

	http.HandleFunc("/peer_certs", sendPeerCerts)
	http.HandleFunc("/headers", sendHeaders)

	go func() {
		log.Fatal(http.ListenAndServe(*http_addr, nil))
	}()

	lh, err := tls.Listen("tcp", *https_addr, tlsconf)
	if err != nil {
		log.Fatal("listen failed: %s", err.Error())
	}
	if err := http.Serve(lh, nil); err != nil {
		log.Fatal("ServeTLS failed: %s", err.Error())
	}
}
