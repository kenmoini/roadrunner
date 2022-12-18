package roadrunner

import (
	"log"
	"path/filepath"
	"strings"

	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/kenmoini/roadrunner/internal/logging"
)

// replaceAtSign replaces the @ sign with the word AT
func replaceAtSign(email string) string {
	// Replace the @ sign with the word AT
	return strings.ReplaceAll(email, "@", "AT")
}

// getHostnameFromURL returns the hostname from a URL
func getHostnameFromURL(url string) string {
	// Get the stuff after the protocol
	hostname := strings.Split(url, "://")[1]

	// Get the stuff before the first slash
	hostname = strings.Split(hostname, "/")[0]

	// Get the stuff before the first colon
	hostname = strings.Split(hostname, ":")[0]

	// Return the hostname
	return hostname
}

// ValidateConfigDirectory just makes sure, that the path provided is a directory,
// or a place where we can create a diretory
func ValidateConfigDirectory(path string) error {
	// Check if the directory exists
	directoryCheck, err := DirectoryExists(path)
	logging.Check(err, "Failed to check if directory exists")

	if directoryCheck {
		// Directory exists - ensure writability
		if IsWritable(path) {
			return nil
		} else {
			return logging.Stoerr("Directory is not writable!")
		}
	} else {
		// Directory doesn't exist - pop off last part of path and check if we have write permissions to create the directory
		parent := filepath.Dir(path)

		if IsWritable(parent) {
			return nil
		} else {
			return logging.Stoerr("Directory does NOT exists AND parent is not writable!")
		}
	}
}

//=================================================================================================
// x509 Helpers
//=================================================================================================

// ReadFileToBytes will return the contents of a file
func ReadFileToBytes(path string) ([]byte, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(absolutePath)
}

// ReadCertFromFile wraps the needed functions to safely read a PEM certificate
func ReadCertFromFile(path string) (*x509.Certificate, error) {
	// Check if the file exists
	certificateFileCheck, err := FileExists(path)
	if !certificateFileCheck {
		return nil, err
	}

	// Read in PEM file
	pem, err := readPEMFile(path, "CERTIFICATE")
	logging.Check(err, "Failed to read the PEM file")

	// Decode to Certfificate object
	return x509.ParseCertificate(pem.Bytes)
}

// readPEMFile reads a PEM file and decodes it, along with a type check
// Types can include CERTIFICATE REQUEST, CERTIFICATE, PRIVATE KEY, PUBLIC KEY
func readPEMFile(path string, matchType string) (*pem.Block, error) {
	fileBytes, err := ReadFileToBytes(path)
	logging.Check(err, "Failed to read the PEM file")

	return decodeByteSliceToPEM(fileBytes, matchType)
}

func decodeByteSliceToPEM(pB []byte, matchType string) (*pem.Block, error) {
	block, rest := pem.Decode(pB)

	if block == nil || block.Type != matchType {
		log.Fatal("failed to decode PEM block containing a " + matchType + ": " + string(rest))
	}

	return block, nil
}
