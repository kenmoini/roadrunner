package roadrunner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/kenmoini/roadrunner/internal/logging"
	"golang.org/x/sys/unix"
)

// DirectoryExists checks if a file exists and returns a boolean or an erro
func DirectoryExists(pathName string) (bool, error) {
	if _, err := os.Stat(pathName); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return false, nil
	}
	if _, err := os.Stat(pathName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return true, nil
	}
	return false, nil
}

// FileExists checks if a file exists and returns a boolean or an erro
func FileExists(fileName string) (bool, error) {
	if _, err := os.Stat(fileName); err == nil {
		// path/to/whatever exists
		return true, nil
	} else if os.IsNotExist(err) {
		// path/to/whatever does *not* exist
		return false, nil
	} else {
		// Schrodinger: file may or may not exist. See err for details.
		// Therefore, do *NOT* use !os.IsNotExist(err) to test for file existence
		return false, err
	}
}

// IsWritable just checks if the path is writable
func IsWritable(path string) bool {
	return unix.Access(path, unix.W_OK) == nil
}

// TouchFile just creates a file if it doesn't exist already
func TouchFile(fileName string, updateTime bool) {
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		file, err := os.Create(fileName)
		logging.Check(err, "Could not create file!")

		defer file.Close()
	} else {
		if updateTime {
			currentTime := time.Now().Local()
			err = os.Chtimes(fileName, currentTime, currentTime)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

// CreateDirectory is self explanitory
func CreateDirectory(path string) {
	//log.Printf("Creating directory %s\n", path)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		logging.Check(errDir, "Could not create directory!")
	}
}

// DeleteFile deletes a file
func DeleteFile(path string) {
	//log.Printf("Deleting %s\n", path)
	e := os.Remove(path)
	logging.Check(e, "Could not delete file!")
}

// writeRSAKeyPair creates key pairs
func writeRSAKeyPair(privKey *bytes.Buffer, pubKey *bytes.Buffer, path string) (bool, bool, error) {
	privKeyFile, err := writeKeyFile(privKey, path+".priv.pem", 0400)
	if err != nil {
		return false, false, err
	}

	pubKeyFile, err := writeKeyFile(pubKey, path+".pub.pem", 0644)
	if err != nil {
		return privKeyFile, false, err
	}
	return privKeyFile, pubKeyFile, nil
}

// writeKeyFile writes a public or private key file depending on the permissions, 644 for public, 400 for private
func writeKeyFile(pem *bytes.Buffer, path string, permission int) (bool, error) {
	pemByte, _ := ioutil.ReadAll(pem)
	keyFile, err := WriteByteFile(path, pemByte, permission, false)
	if err != nil {
		return false, err
	}
	return keyFile, nil
}

// EncodeECDSAPrivateKeyPEM takes a ecdsa.PrivateKey directly and encodes it to a PEM block
func EncodeECDSAPrivateKeyPEM(privateKey *ecdsa.PrivateKey) (string, []byte) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		logging.Check(err, "Failed to marshal ECDSA private key")
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), pemEncoded
}

// DecodeECDSAPrivateKeyPEM takes a ecdsa.PrivateKey directly and encodes it to a PEM block
func DecodeECDSAPrivateKeyPEM(path string) *ecdsa.PrivateKey {
	pemEncoded := LoadKeyFile(path)
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		logging.Check(err, "Failed to parse ECDSA private key")
	}

	return privateKey
}

// LoadKeyFile - loads a PEM key file
func LoadKeyFile(fileName string) []byte {
	inFile, err := ioutil.ReadFile(fileName)
	logging.Check(err, "Failed to read key file: "+fileName)
	return inFile
}

// WriteByteFile creates a file from a byte slice with an optional filemode, only if it's new, and populates it - can force overwrite optionally
func WriteByteFile(path string, content []byte, mode int, overwrite bool) (bool, error) {
	var fileMode os.FileMode
	if mode == 0 {
		fileMode = os.FileMode(0600)
	} else {
		fileMode = os.FileMode(mode)
	}
	fileCheck, err := FileExists(path)
	logging.Check(err, "Failed to check if file exists")

	// If not, create one with a starting digit
	if !fileCheck {
		err = ioutil.WriteFile(path, content, fileMode)
		logging.Check(err, "Failed to write file")
		return true, err
	}
	// If the file exists and we want to overwrite it
	if fileCheck && overwrite {
		err = ioutil.WriteFile(path, content, fileMode)
		logging.Check(err, "Failed to overwrite file")
		return true, err
	}
	return false, nil
}
