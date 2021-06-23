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
	"os/user"
	"strconv"
	"syscall"
	"time"
)

var (
	port    = flag.Int("port", 1344, "ICAP listen port")
	istag   = flag.String("istag", "SIDEWAYS-ICAP", "ICAP ISTag value")
	verbose = flag.Bool("verbose", false, "Be more verbose")
	cfg     = flag.String("cfg", "/etc/icapd.conf", "ICAP JSON configuration")
	uid     = flag.String("uid", "", "Running UID")
	gid     = flag.String("gid", "", "Running GID")
	check   = flag.Bool("check", false, "Check config syntax and exit")
)

type httpValues struct {
	fullSize uint64
	method   string
	host     string
}

var acl []ruleSpec

type ruleSpec struct {
	rule rule
}

func (rs *ruleSpec) UnmarshalJSON(b []byte) error {
	var j map[string]*json.RawMessage
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	for k, v := range j {
		switch k {
		case "allow":
			var ar allowRule
			if err := json.Unmarshal([]byte(*v), &ar); err != nil {
				return err
			}
			rs.rule = ar
		case "deny":
			var dr denyRule
			if err := json.Unmarshal([]byte(*v), &dr); err != nil {
				return err
			}
			rs.rule = dr
		default:
			return fmt.Errorf("unknown rule '%s'", k)
		}
	}
	return nil
}

func (rs *ruleSpec) Eval(w icap.ResponseWriter, v *httpValues) (bool, error) {
	var conditions []conditionSpec
	switch rs.rule.(type) {
	case allowRule:
		conditions = rs.rule.(allowRule).Conditions
	case denyRule:
		conditions = rs.rule.(denyRule).Conditions
	}

	for _, cond := range conditions {
		vout("Condition: %v\n", cond)
		match, err := cond.condition.Eval(v)
		if err != nil {
			log.Printf("reqmodCheck: error: %v", err)
			return false, httpError(w, 500, "reqmodCheck: error: %v", err)
		}
		if !match {
			return false, nil
		}
	}
	return true, rs.rule.Execute(w)
}

type rule interface {
	Execute(w icap.ResponseWriter) error
}

type allowRule struct {
	Conditions []conditionSpec `json:"conditions"`
	Comment    string          `json:"comment,omitempty"`
}

func (r allowRule) Execute(w icap.ResponseWriter) error {
	w.WriteHeader(204, nil, false)
	return nil
}

type denyRule struct {
	Conditions []conditionSpec `json:"conditions"`
	HttpCode   int             `json:"http_code,omitempty"`
	Body       string          `json:"body,omitempty"`
	Comment    string          `json:"comment,omitempty"`
}

func (r denyRule) Execute(w icap.ResponseWriter) error {
	code := 403
	if r.HttpCode != 0 {
		code = r.HttpCode
	}
	return httpError(w, code, r.Body)
}

type conditionSpec struct {
	condition condition
}

func (cs *conditionSpec) UnmarshalJSON(b []byte) error {
	var j map[string]*json.RawMessage
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	for k, v := range j {
		switch k {
		case "host":
			var c hostCondition
			if err := json.Unmarshal([]byte(*v), &c.host); err != nil {
				return err
			}
			cs.condition = c
		case "body_size_gt":
			var c bodySizeGtCondition
			if err := json.Unmarshal([]byte(*v), &c.size); err != nil {
				return err
			}
			cs.condition = c
		case "body_size_lt":
			var c bodySizeLtCondition
			if err := json.Unmarshal([]byte(*v), &c.size); err != nil {
				return err
			}
			cs.condition = c
		default:
			return fmt.Errorf("unknown condition '%s'", k)
		}
	}
	return nil
}

type condition interface {
	Eval(v *httpValues) (bool, error)
}

type hostCondition struct {
	host string
}

func (c hostCondition) Eval(v *httpValues) (bool, error) {
	return c.host == v.host, nil
}

type bodySizeGtCondition struct {
	size uint64
}

func (c bodySizeGtCondition) Eval(v *httpValues) (bool, error) {
	return v.fullSize > c.size, nil
}

type bodySizeLtCondition struct {
	size uint64
}

func (c bodySizeLtCondition) Eval(v *httpValues) (bool, error) {
	return v.fullSize < c.size, nil
}

func vout(f string, args ...interface{}) {
	if *verbose {
		log.Printf(f, args...)
	}
}

func httpError(w icap.ResponseWriter, code int, body string, args ...interface{}) error {
	var status string
	switch code {
	case 403:
		status = "Forbidden"
	case 413:
		status = "Payload Too large"
	case 500:
		status = "Internal error"
	default:
		status = "Internal error"
		body = fmt.Sprintf("Unhandled error code %d", code)
		code = 500
	}

	resp := &http.Response{
		Status:        status,
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header, 0),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")
	msg := fmt.Sprintf(body, args...)
	vout("httpError: %d %s (%s)", code, status, msg)
	if len(body) == 0 {
		w.WriteHeader(200, resp, false)
	} else {
		w.WriteHeader(200, resp, true)
		b := []byte(msg)
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("httpError: Write: %v", err)
		}
	}
	return nil
}

func analyzeReq(req *icap.Request) (*httpValues, error) {
	buf := make([]byte, 4096)

	v := &httpValues{
		method:   req.Request.Method,
		host:     req.Request.Host,
		fullSize: 0,
	}

	for {
		n, err := req.Request.Body.Read(buf)
		vout("read chunk; n = %d", n)
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

	start := time.Now()
	v, err := analyzeReq(req)
	end := time.Now()
	elapsed := end.Sub(start)

	vout("httpValues: %v", v)

	if err != nil {
		httpError(w, 500, fmt.Sprintf("analyzeReq: %v", err))
		return
	}
	vout("analysis complete; %v elapsed", elapsed)

	vout("evaluating rules...")
	start = time.Now()
	defer func() {
		end = time.Now()
		elapsed = end.Sub(start)
		vout("rule evaluation complete; %v elapsed", elapsed)
	}()

	for _, rule := range acl {
		match, err := rule.Eval(w, v)
		if err != nil {
			log.Printf("reqmodCheck: %v", err)
			return
		}
		if match {
			return
		}
	}

	// If no rules match, we allow.
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

	if err := json.Unmarshal(data, &acl); err != nil {
		log.Fatalf("json: %v", err)
	}

	vout("acl: %v", acl)

	if *check {
		return
	}

	if *gid != "" {
		g, err := user.LookupGroup(*gid)
		if err != nil {
			log.Fatalf("user.LookupGroup: %v", err)
		}
		n, err := strconv.Atoi(g.Gid)
		if err != nil {
			log.Fatalf("bad GID conversion: %v", err)
		}
		if err := syscall.Setregid(n, n); err != nil {
			log.Fatalf("syscall.Setegid: %v", err)
		}
	}
	if *uid != "" {
		u, err := user.Lookup(*uid)
		if err != nil {
			log.Fatalf("user.Lookup: %v", err)
		}
		n, err := strconv.Atoi(u.Uid)
		if err != nil {
			log.Fatalf("bad GID conversion: %v", err)
		}
		if err := syscall.Setreuid(n, n); err != nil {
			log.Fatalf("syscall.Seteuid: %v", err)
		}
	}

	icap.HandleFunc("/acl", aclCheck)
	icap.ListenAndServe(fmt.Sprintf(":%d", *port), icap.HandlerFunc(aclCheck))
}
