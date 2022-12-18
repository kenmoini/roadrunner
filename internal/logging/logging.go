package logging

import (
	"log"
	"net/http"
	"strings"
)

// logNetworkRequestStdOut adds a logger wrapper to add extra network client information to the log
func LogNetworkRequestStdOut(s string, r *http.Request) {
	LogStdOutInfo("IP[" + ReadUserIP(r) + "] UA[" + r.UserAgent() + "] " + string(s))
	//log.Printf("[%s] %s\n", ReadUserIP(r), string(s))
}

// logStdOut just logs something to stdout
func LogStdOut(s string) {
	log.Printf("%s\n", string(s))
}

// LogStdOutInfo just logs something to stdout with an info tag
func LogStdOutInfo(s string) {
	log.Printf("[INFO] %s\n", string(s))
}

// LogStdOutWarn just logs something to stdout with a warn tag
func LogStdOutWarn(s string) {
	log.Printf("[WARN] %s\n", string(s))
}

// logStdErr just logs to stderr
func LogStdErr(s string) {
	log.Fatalf("[ERROR] %s\n", string(s))
}

// Stoerr wraps a string in an error object
func Stoerr(s string) error {
	return &errorString{s}
}

// check does error checking
func Check(e error, message string) {
	if e != nil {
		log.Printf("[ERROR] %s - %v", message, e)
	}
}

// checkAndFail checks for an error type and fails
func CheckAndFail(e error, message string) {
	if e != nil {
		log.Fatalf("[FAIL] %s - %v", message, e)
	}
}

/*************************************************************************************
* IP Resolution
*************************************************************************************/

// ReadUserIP gets the requesting client's IP so you can do a reverse DNS lookup
func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}

// ReadUserIPNoPort gets the requesting client's IP without the port so you can do a reverse DNS lookup
func ReadUserIPNoPort(r *http.Request) string {
	IPAddress := ReadUserIP(r)

	NoPort := strings.Split(IPAddress, ":")
	if len(NoPort) > 0 {
		NoPort = NoPort[:len(NoPort)-1]
	}
	JoinedAddress := strings.Join(NoPort[:], ":")
	return JoinedAddress
}
