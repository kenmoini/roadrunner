package roadrunner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/kenmoini/roadrunner/internal/helpers"
	"github.com/kenmoini/roadrunner/internal/logging"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

type Order struct {
	Domains []string `yaml:"domains"`
	Email   string   `yaml:"email,omitempty"`
}

type OrderResponse struct {
	Status         string `yaml:"status"`
	Expires        string `yaml:"expires"`
	CertificatePEM string `yaml:"certificate_pem"`
	PrivateKeyPEM  string `yaml:"private_key_pem"`
}

// ConnectionInfo is the information needed to connect to an ACME server
type ConnectionInfo struct {
	DirectoryURL  string                  `yaml:"directory_url"`
	SkipTLSVerify bool                    `yaml:"skip_tls_verify,omitempty"`
	Solvers       map[string]acmez.Solver `yaml:"solvers,omitempty"`
}

// mySolver is a no-op acmez.Solver for example purposes only.
type mySolver struct{}

// CreateACMEClient creates a new ACME client
func CreateACMEClient(cInfo ConnectionInfo, solvers map[string]acmez.Solver, logger *zap.Logger) acmez.Client {

	// A high-level client embeds a low-level client and makes
	// the ACME flow much easier, but with less flexibility
	// than using the low-level API directly (see other example).
	//
	// One thing you will have to do is provide challenge solvers
	// for all the challenge types you wish to support. I recommend
	// supporting as many as possible in case there are errors. The
	// library will try all enabled challenge types, and certain
	// external factors can cause certain challenge types to fail,
	// where others might still succeed.
	//
	// Implementing challenge solvers is outside the scope of this
	// example, but you can find a high-quality, general-purpose
	// solver for the dns-01 challenge in CertMagic:
	// https://pkg.go.dev/github.com/caddyserver/certmagic#DNS01Solver

	client := acmez.Client{
		Client: &acme.Client{
			Directory: cInfo.DirectoryURL,
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: cInfo.SkipTLSVerify, // REMOVE THIS FOR PRODUCTION USE!
					},
				},
			},
			Logger: logger,
		},
	}

	// Return the client
	return client
}

// CreateACMEClientAccountKeyFile creates a new ACME client account key file if needed or returns it if it already exists
// The account key files will be found in the working_directory/.acme/keys/<endpoint-server-hostname>/<emailAT>.key path.
func CreateACMEClientAccountKeyFile(email string, cInfo ConnectionInfo) (*ecdsa.PrivateKey, error) {
	sanitizedEmail := replaceAtSign(email)
	endpointServerHostname := getHostnameFromURL(cInfo.DirectoryURL)
	endpointServerHostnamePath := helpers.AppendSlash(RunningConfig.Roadrunner.Config.WorkingDir) + ".acme/keys/" + endpointServerHostname
	accountKeyFilePath := endpointServerHostnamePath + "/" + sanitizedEmail + ".key"

	// Check to see if the endpoint server hostname path exists
	pathCheck, err := DirectoryExists(endpointServerHostnamePath)
	if err != nil {
		return nil, err
	}

	// If the endpoint server hostname path does not exist, create it
	if !pathCheck {
		CreateDirectory(endpointServerHostnamePath)
	}

	// Check to see if the key file exists
	keyFileCheck, err := FileExists(accountKeyFilePath)
	if err != nil {
		return nil, err
	}

	// If the key file does not exist, create it
	if !keyFileCheck {
		// Generate a new private key
		accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		_, pemBytes := EncodeECDSAPrivateKeyPEM(accountPrivateKey)
		err = ioutil.WriteFile(accountKeyFilePath, pemBytes, 0600)
		if err != nil {
			return nil, err
		}

		return accountPrivateKey, nil

	} else {
		// Read in the key file now
		readKey := DecodeECDSAPrivateKeyPEM(accountKeyFilePath)
		logging.LogStdOutInfo("Loaded key file: " + accountKeyFilePath)

		return readKey, nil

	}

}

// CreateACMEClientAccount creates a new ACME client account
// An account is a combination of email address and private key that is used to identify you to the ACME CA.
// You only need to create an account once, and then you can use it to get as many certificates as you want.
// The files are stored in the working_directory/.acme/accounts/<endpoint-server-hostname>/<email>/ directories.
func CreateACMEClientAccount(email string, client acmez.Client, logger *zap.Logger) (acme.Account, error) {
	// A context allows us to cancel long-running ops
	ctx := context.Background()

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates!

	accountPrivateKey, err := CreateACMEClientAccountKeyFile(email, ConnectionInfo{DirectoryURL: client.Client.Directory})
	if err != nil {
		return acme.Account{}, err
	}

	// DEBUG
	// Print out the accountPrivateKey
	logger.Debug("Account Private Key", zap.String("private_key", fmt.Sprintf("%v", accountPrivateKey)))

	// Create the Account Object
	account := acme.Account{
		Contact:              []string{"mailto:" + email},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return acme.Account{}, fmt.Errorf("new account error: %v", err)
	}

	// Return the account
	return account, err
}

func (s mySolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s mySolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}
