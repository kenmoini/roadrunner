package roadrunner

// CLIOpts contains the CLI options
type CLIOpts struct {
	Config string
}

// Config struct for webapp config at the top level
type Config struct {
	Roadrunner Roadrunner `yaml:"roadrunner"`
}

// Roadrunner is the structure that houses the root of the configuration
type Roadrunner struct {
	// Config is the configuration of this instance
	Config AppConfig `yaml:"config,omitempty"`
	// Certificates is the list of certificates to generate and/or renew
	Certificates []Certificate `yaml:"certificates"`
	// Issuers is the list of issuers to use for generating and/or renewing certificates
	Issuers []Issuer `yaml:"issuers"`
}

// Config is the structure that houses the general configuration
type AppConfig struct {
	// Mode is the mode to run the application in, options are "daemon" and "cli", defaulting to "cli"
	Mode string `yaml:"mode,omitempty"`
	// HTTPProxy is the HTTP proxy to use for outbound connections
	HTTPProxy string `yaml:"http_proxy,omitempty"`
	// HTTPSProxy is the HTTPS proxy to use for outbound connections
	HTTPSProxy string `yaml:"https_proxy,omitempty"`
	// NoProxy is the list of domains to not use the proxy for
	NoProxy []string `yaml:"no_proxy,omitempty"`
	// SkipTLSVerify is a global flag to enable/disable SSL verification
	SkipTLSVerify bool `yaml:"skip_tls_verify,omitempty"`
	// WorkingDir is the directory to use for storing generated files
	WorkingDir string `yaml:"working_dir,omitempty"`
}

// Certificate is the struct for the ssl certificate to generate/renew
type Certificate struct {
	// Issuer is the name of the ACME solver as an Issuer
	Issuer string `yaml:"issuer"`
	// Email is the email address used when registering with the ACME endpoint
	Email string `yaml:"email"`
	// Domains is a list of domains to generate a certificate for
	Domains []string `yaml:"domains"`
	// SaveType is the type of data that will be stored in the save path, options are "pem-pair" and "haproxy"
	SaveType string `yaml:"save_type"`
	// SavePath is the optional directory where the files generated will be COPIED to
	// If the directory does not exist, it will be created
	// The files saved will be named after the domain name and .crt and optionally the .key file as well if using pem-pair
	SavePaths SavePaths `yaml:"save_paths,omitempty"`
	// RestartCmd is the command that will be run after the certificate is generated or renewed
	RestartCmd string `yaml:"restart_cmd,omitempty"`
	// RenewDays is the number of days before the certificate expires that it will be renewed
	RenewDays int `yaml:"renew_days,omitempty"`
	// RequestOptions is the list of options that are used when requesting the certificate
	RequestOptions RequestOptions `yaml:"request_options,omitempty"`
}

// SavePaths is a grouping of the possible assets saved by the application
type SavePaths struct {
	// Cert is the path to the certificate
	Cert string `yaml:"cert"`
	// Key is the path to the private key
	Key string `yaml:"key,omitempty"`
}

// Issuer provides the connection information for the ACME server solver
type Issuer struct {
	// Name is the name of the solver to use
	Name string `yaml:"name"`
	// Type is the type of solver to use, options are "none", "http" and "dns-01"
	Type string `yaml:"type"`
	// Endpoint is the endpoint URL for the solver directory
	Endpoint string `yaml:"endpoint"`
	// CAFile is an optional path to a CA file to use for the solver
	CAFile string `yaml:"ca_file,omitempty"`
	// SkipTLSVerify is a flag to enable/disable SSL verification
	SkipTLSVerify bool `yaml:"skip_tls_verify,omitempty"`
}

// RequestOptions is the struct for the options used when requesting the certificate
type RequestOptions struct {
	// KeyType is the type of key to use, options are "rsa" and "ecdsa"
	KeyType string `yaml:"key_type,omitempty"`
	// KeySize is the size of the key to use, options are 2048, 4096, and 8192
	KeySize int `yaml:"key_size,omitempty"`
	// Expiration is the number of days the certificate will be valid for
	Expiration int `yaml:"expiration,omitempty"`
}
