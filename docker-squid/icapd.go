// Sideways ICAP daemon, see RFC 3507.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-icap/icap"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

var (
	port = flag.Int("port", 1344, "ICAP listen port")
	istag = flag.String("istag", "SIDEWAYS-ICAP", "ICAP ISTag value")
	verbose = flag.Bool("verbose", false, "Be more verbose")
	cfg = flag.String("cfg", "/etc/icapd.conf", "ICAP JSON configuration")
)

var acls []AclSpec

type httpValues struct {
	fullSize uint64
	method string
	host string
}

type AclSpec struct {
	Attr string
	Verb string
	Value string
}

func vout(f string, args ...interface{}) {
	if *verbose {
		log.Printf(f, args...)
	}
}

func httpError(w icap.ResponseWriter, code int, body string, args ...interface{}) {
	var status string
	switch code {
	case 403:
		status = "Forbidden"
	case 500:
		status = "Internal error"
	default:
		code = 500
		status = "Internal error"
		body = "Undefined error code"
	}

	resp := &http.Response{
		Status: status,
		StatusCode: code,
		Proto: "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: make(http.Header, 0),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")
	if len(body) == 0 {
		w.WriteHeader(403, resp, false)
	} else {
		w.WriteHeader(403, resp, true)
		b := []byte(fmt.Sprintf(body, args...))
		if _, err := w.Write(b); err != nil {
			log.Printf("httpError: write: %v", err)
		}
	}
}

func analyzeReq(req *icap.Request) (*httpValues, error) {
	buf := make([]byte, 4096)
	rd := io.LimitReader(req.Request.Body, 4096)

	v := &httpValues{
		method: req.Request.Method,
		host: req.Request.Host,
		fullSize: 0,
	}

	for {
		n, err := rd.Read(buf)
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		v.fullSize += uint64(n)
	}

	return v, nil
}

func reqmodCheck(w icap.ResponseWriter, req *icap.Request) {
	vout("analyzing...")
	v, err := analyzeReq(req)
	if err != nil {
		httpError(w, 500, fmt.Sprintf("analyzeReq: %v", err))
		return
	}

	for _, a := range acls {
		switch a.Attr {
		case "size":
			if a.Verb != ">" {
				log.Fatalf("unsupported verb %s for attribute 'size'", a.Verb)
			}
			sz, err := strconv.ParseInt(a.Value, 10, 64)
			if err != nil {
				log.Fatal("value for 'size' attribute is not integer")
			}
			if v.fullSize > uint64(sz) {
				httpError(w, 403, "payload larger than %d bytes: %d", sz, v.fullSize)
				return
			}
		default:
			log.Fatalf("unknown attribute %s", a.Attr)
		}
	}

	w.WriteHeader(204, nil, false)
}

func aclCheck(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", *istag)
	h.Set("Service", "Sideways ICAP")

	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD")
		h.Set("Allow", "204")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		if *verbose {
			log.Printf("REQMOD %s", req.Request.Host)
		}
		reqmodCheck(w, req)
	default:
		w.WriteHeader(405, nil, false)
		log.Println("Invalid request method: %s", req.Method)
	}
}

func main() {
	flag.Parse()
	data, err := ioutil.ReadFile(*cfg)
	if err != nil {
		log.Fatalf("cfg: %v", err)
	}

	if err := json.Unmarshal(data, &acls); err != nil {
		log.Fatalf("json: %v", err)
	}

	vout("acls: %v", acls)

	icap.HandleFunc("/acl", aclCheck)
	icap.ListenAndServe(fmt.Sprintf(":%d", *port), icap.HandlerFunc(aclCheck))
}
