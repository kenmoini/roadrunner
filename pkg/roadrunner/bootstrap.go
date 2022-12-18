package roadrunner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/kenmoini/roadrunner/internal/helpers"
	"github.com/kenmoini/roadrunner/internal/logging"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// Entrypoint is the entry point for the roadrunner application, keeps things small and tidy
func Entrypoint() {

	// Generate our config based on the config supplied
	// by the user in the flags
	cfgPath, err := ParseFlags()
	logging.CheckAndFail(err, "Failed to parse CLI Opt flags", true)

	// Run general preflight
	PreflightSetup()

	// Setup engine config
	cfg, err := NewConfig(cfgPath)
	logging.CheckAndFail(err, "Failed to parse application configuration", true)
	RunningConfig = cfg

	// Run the engine in the mode specified in the configuration
	switch cfg.Roadrunner.Config.Mode {
	case "daemon":
		// Run the daemon preflight
		DaemonPreflightSetup()

		// Start processing the certificates
		cfg.ProcessConfiguration()

	case "cli":
		// Run the CLI preflight
		CLIPreflightSetup()

		// Start processing the certificates
		cfg.ProcessConfiguration()

	default:
		logging.LogStdOutWarn("No/Invalid mode specified in configuration!  Proceeding as default CLI mode...")
		// Run the CLI preflight
		CLIPreflightSetup()

		// Start processing the certificates
		cfg.ProcessConfiguration()
	}
}

// ProcessConfiguration will process the Roadrunner configuration
func (config Config) ProcessConfiguration() {

	// Logging is important - replace with your own zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		logging.LogErrorToStdErr(err)
	}

	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	// Create the Working Directory if it doesn't exist
	// Check to see if the working directory configuration is set - if not use the default
	if config.Roadrunner.Config.WorkingDir == "" {
		logging.LogStdOutInfo("Working directory not specified in configuration, using default " + DefaultWorkingDirectory + "...")
		config.Roadrunner.Config.WorkingDir = DefaultWorkingDirectory
		RunningConfig.Roadrunner.Config.WorkingDir = helpers.AppendSlash(DefaultWorkingDirectory)
	}

	// Check to see if the working directory exists - if not create it
	if _, err := os.Stat(config.Roadrunner.Config.WorkingDir); os.IsNotExist(err) {
		logging.LogStdOutInfo(fmt.Sprintf("Working directory [%v] does not exist, creating it now...", config.Roadrunner.Config.WorkingDir))
		mkerr := os.MkdirAll(config.Roadrunner.Config.WorkingDir, 0755)
		if mkerr != nil {
			logging.CheckAndFail(mkerr, "Failed to create working directory", true)
		}
	}

	// Make a few extra directories
	livemkerr := os.MkdirAll(helpers.AppendSlash(config.Roadrunner.Config.WorkingDir)+".acme/live", 0755)
	if livemkerr != nil {
		logging.CheckAndFail(livemkerr, "Failed to create live directory", true)
	}
	archmkerr := os.MkdirAll(helpers.AppendSlash(config.Roadrunner.Config.WorkingDir)+".acme/archive", 0755)
	if archmkerr != nil {
		logging.CheckAndFail(archmkerr, "Failed to create archive directory", true)
	}
	keysmkerr := os.MkdirAll(helpers.AppendSlash(config.Roadrunner.Config.WorkingDir)+".acme/keys", 0755)
	if keysmkerr != nil {
		logging.CheckAndFail(keysmkerr, "Failed to create keys directory", true)
	}

	// Set the base path for different directories
	basePath := helpers.AppendSlash(config.Roadrunner.Config.WorkingDir)
	var issuers = config.Roadrunner.Issuers

	// Loop through the Certificates and process them
	for i, cert := range config.Roadrunner.Certificates {
		// Log out the start of the process
		logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Starting to process certificate...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))

		// Set some defaults and facts
		spExists := false
		localExists := false
		localCertPath := basePath + ".acme/live/" + cert.Domains[0] + "/cert.pem"
		account := acme.Account{}
		client := acmez.Client{}

		// A context allows us to cancel long-running ops
		ctx := context.Background()

		if cert.SaveType == "" {
			cert.SaveType = "pem-pair"
		}

		// Check to see if we can connect to the Issuer
		// Get the matching named issuer
		idx := slices.IndexFunc(issuers, func(i Issuer) bool { return i.Name == cert.Issuer })
		if idx == -1 {
			logging.CheckAndFail(fmt.Errorf("[%d / %d - %v] Failed to find matching issuer [%v] in the configuration", i+1, len(config.Roadrunner.Certificates), cert.Domains[0], cert.Issuer), "Failed to find the issuer in the configuration", false)
		} else {
			logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Found matching issuer [%v] in the configuration...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0], cert.Issuer))
			matchingIssuer := issuers[idx]
			fmt.Println(matchingIssuer)
			// Try connecting to the Issuer

			// Assemble the ConnectionInfo struct
			cInfo := ConnectionInfo{
				DirectoryURL:  matchingIssuer.Endpoint,
				SkipTLSVerify: matchingIssuer.SkipTLSVerify,
			}

			// Create a new client
			solvers := map[string]acmez.Solver{
				acme.ChallengeTypeHTTP01:    mySolver{}, // provide these!
				acme.ChallengeTypeDNS01:     mySolver{}, // provide these!
				acme.ChallengeTypeTLSALPN01: mySolver{}, // provide these!
			}

			// Create an ACME client
			client = CreateACMEClient(cInfo, solvers, logger)

			// Create a new Account
			account, err = CreateACMEClientAccount(cert.Email, client, logger)
			if err != nil {
				logging.CheckAndFail(err, "Failed to create the ACME client account", false)
			}
			//fmt.Println(account.Location)

			if account.Status == "valid" {
				logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Successfully created an ACME client account...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
			} else {
				logging.CheckAndFail(fmt.Errorf("[%d / %d - %v] Failed to create an ACME client account", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]), "Failed to create an ACME client account", false)
			}

		}

		// Check to see if the SavePath is specified, if so check it for a valid cert
		if cert.SavePaths.Cert != "" {
			// Check to see if the SavePath exists in the specified format
			spCheck, err := FileExists(cert.SavePaths.Cert)
			if err != nil {
				logging.CheckAndFail(err, "Failed to check for the save path certificate file", true)
			}

			// If the file exists, check to see if it's expired
			if spCheck {
				spExists = true
				logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate file already exists in the specified SavePath, checking to see if it's expired...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
			} else {
				logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate file does not exist in the specified SavePath...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
			}
		}
		// If this is a pem-pair check for the key too
		if cert.SaveType == "pem-pair" {
			if cert.SavePaths.Key != "" {
				// Check to see if the SavePath exists in the specified format
				spKeyCheck, err := FileExists(cert.SavePaths.Key)
				if err != nil {
					logging.CheckAndFail(err, "Failed to check for the save path certificate key file", true)
				}

				// If the file exists, check to see if it's expired
				if spKeyCheck {
					spExists = true
					logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate key file already exists in the specified SavePath...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
				} else {
					logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate key file does not exist in the specified SavePath...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
				}
			}
		}

		// DEBUG: printout if spExists is true or false
		logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] spExists: %v", i+1, len(config.Roadrunner.Certificates), cert.Domains[0], spExists))

		// Check to see if the certificate already exists in the local location
		localCheck, err := FileExists(localCertPath)
		if err != nil {
			logging.CheckAndFail(err, "Failed to check for the local certificate file", true)
		}

		// If the file exists, check to see if it's expired
		if localCheck {
			localExists = true
			logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate file already exists in the local location, checking to see if it's expired...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
			// Check for validity
			// If Valid:
			// - Check to see if SavePath was specified but not found - copy if so
			// - Log out that it's valid and skip
			// If Invalid:
			// - Renew
			// - Check to see if SavePath is specified - copy if so
			// - log out that it's been renewed and copied
		} else {
			logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Certificate file does not exist in the local location, creating it now...", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
			// Create the certificate

			// Every certificate needs a key.
			certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				fmt.Errorf("generating certificate key: %v", err)
			}

			// Once your client, account, and certificate key are all ready,
			// it's time to request a certificate! The easiest way to do this
			// is to use ObtainCertificate() and pass in your list of domains
			// that you want on the cert. But if you need more flexibility, you
			// should create a CSR yourself and use ObtainCertificateUsingCSR().
			certs, err := client.ObtainCertificate(ctx, account, certPrivateKey, cert.Domains)
			if err != nil {
				fmt.Errorf("obtaining certificate: %v", err)
			}

			// ACME servers should usually give you the entire certificate chain
			// in PEM format, and sometimes even alternate chains! It's up to you
			// which one(s) to store and use, but whatever you do, be sure to
			// store the certificate and key somewhere safe and secure, i.e. don't
			// lose them!
			for _, cert := range certs {
				fmt.Printf("Certificate %q:\n%s\n\n", cert.URL, cert.ChainPEM)
			}

			// Check to see if SavePath is specified - copy if so
			// Log out that it's been created and copied
		}

		// DEBUG: printout if localExists is true or false
		logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] localExists: %v", i+1, len(config.Roadrunner.Certificates), cert.Domains[0], localExists))

		// Log out the end of the process
		logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Finished processing certificate", i+1, len(config.Roadrunner.Certificates), cert.Domains[0]))
	}

	// // Loop through the Issuers and process them as Clients
	// for i, issuer := range config.Roadrunner.Issuers {
	// 	// Log out the start of the process
	// 	logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Starting to process issuer...", i+1, len(config.Roadrunner.Issuers), issuer.Name))

	// 	// Assemble the ConnectionInfo struct
	// 	cInfo := ConnectionInfo{
	// 		DirectoryURL:  issuer.Endpoint,
	// 		SkipTLSVerify: issuer.SkipTLSVerify,
	// 	}

	// 	// Assemble the OrderRequest struct
	// 	oReq := Order{
	// 		Email: issuer.Email,
	// 		Domains: ,

	// 	// Create a new client
	// 	solvers := map[string]acmez.Solver{
	// 		acme.ChallengeTypeHTTP01:    mySolver{}, // provide these!
	// 		acme.ChallengeTypeDNS01:     mySolver{}, // provide these!
	// 		acme.ChallengeTypeTLSALPN01: mySolver{}, // provide these!
	// 	}

	// 	client := CreateACMEClient(cInfo, solvers, logger)

	// 	// DEBUG: Print out the client
	// 	logging.LogStdOutInfo(fmt.Sprintf("Client: %+v", client))

	// 	// Create the ACME account
	// 	account := CreateACMEClientAccount(client, )

	// 	// Log out the end of the process
	// 	logging.LogStdOutInfo(fmt.Sprintf("[%d / %d - %v] Finished processing issuer", i+1, len(config.Roadrunner.Issuers), issuer.Name))
	// }

	// Block on this channel listeninf for those previously defined syscalls assign
	// to variable so we can let the user know why the app is shutting down
	interrupt := <-runChan

	// If we get one of the pre-prescribed syscalls, gracefully terminate the app
	// while alerting the user
	logging.LogStdOutInfo(fmt.Sprintf("Roadrunner is shutting down due to %+v\n", interrupt))

}

//=================================================================================================
// Preflight Functions
//=================================================================================================

// PreflightSetup just makes sure the stage is set before starting the application in general
func PreflightSetup() {
	logging.LogStdOutInfo("Preflight complete!")
}

// CLIPreflightSetup just makes sure the stage is set before starting the CLI applet
func CLIPreflightSetup() {
	logging.LogStdOutInfo("CLI Mode Preflight complete!")
}

// DaemonPreflightSetup just makes sure the stage is set before starting the daemon
func DaemonPreflightSetup() {
	logging.LogStdOutInfo("Daemon Mode Preflight complete!")
}

// HybridPreflightSetup just makes sure the stage is set before starting each component
func HybridPreflightSetup() {
	// Run the CLI preflight
	CLIPreflightSetup()

	// Run the daemon preflight
	DaemonPreflightSetup()

	// Log that the preflight is complete
	logging.LogStdOutInfo("Hybrid Mode Preflight complete!")
}

//=================================================================================================
// CLI Option Parsing
//=================================================================================================

// ParseFlags will define and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (CLIOpts, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "", "path to config file, eg '-config=./config.yml'")

	// Actually parse the flags
	flag.Parse()

	if configPath == "" {
		return CLIOpts{}, logging.Stoerr("No server configuration defined! (-config=./config.yml)")
	} else {
		// Validate the path first
		if err := ValidateConfigPath(configPath); err != nil {
			return CLIOpts{}, err
		}
	}

	SetCLIOpts := CLIOpts{
		Config: configPath}

	// Return the configuration path
	return SetCLIOpts, nil
}

//=================================================================================================
// Configuration Loading
//=================================================================================================

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath CLIOpts) (*Config, error) {
	// Create config structure
	config := &Config{}

	// Open config file
	file, err := os.Open(configPath.Config)
	logging.CheckAndFail(err, "Failed to open config file", true)
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	//readConfig = config

	return config, nil
}
