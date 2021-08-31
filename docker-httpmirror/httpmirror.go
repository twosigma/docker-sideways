package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	http_addr  = flag.String("http_addr", ":8080", "HTTP listen address")
	https_addr = flag.String("https_addr", ":8443", "HTTPS listen address")
	ca         = flag.String("ca", "/etc/ssl/certs/ca-certificates.crt", "CA certificates file")
	crt        = flag.String("crt", "cert.pem", "Server certificate")
	key        = flag.String("key", "key.pem", "Server key")
	allow      = flag.String("allow", "127.0.0.1/32,::1/128", "Comma-separated list of allowed subnets")
)

var allowed_subnets []*net.IPNet

func allowed(res http.ResponseWriter, req *http.Request) bool {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "Could not parse HTTP request RemoteAddr: %s\n", req.RemoteAddr)
		return false
	}

	client_ip := net.ParseIP(host)
	if client_ip == nil {
		res.WriteHeader(500)
		fmt.Fprintf(res, "HTTP request RemoteAddr IP is invalid: %s\n", host)
		return false
	}

	for _, c := range allowed_subnets {
		if c.Contains(client_ip) {
			return true
		}
	}

	res.WriteHeader(403)
	fmt.Fprintf(res, "IP address %s is not allowed\n", client_ip)
	return false
}

func sendPeerCerts(res http.ResponseWriter, req *http.Request) {
	if !allowed(res, req) {
		return
	}

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
	fmt.Fprint(res, string(j)+"\n")
}

func sendHeaders(res http.ResponseWriter, req *http.Request) {
	if !allowed(res, req) {
		return
	}

	h := make(map[string][]string)
	h["Host"] = append(h["Host"], req.Host)
	for k, v := range req.Header {
		h[k] = v
	}

	j, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprint(res, string(j)+"\n")
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
	flag.Parse()

	if *allow != "" {
		for _, cidr_str := range strings.Split(*allow, ",") {
			_, c, err := net.ParseCIDR(cidr_str)
			if err != nil {
				log.Fatal("bad network spec: %s", err.Error())
			}
			allowed_subnets = append(allowed_subnets, c)
		}
	}

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
