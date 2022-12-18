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
	Config AppConfig `json:"config,omitempty"`
	// Certificates is the list of certificates to generate and/or renew
	Certificates []Certificate `json:"certificates"`
}

// Config is the structure that houses the general configuration
type AppConfig struct {
	// HTTPProxy is the HTTP proxy to use for outbound connections
	HTTPProxy string `json:"http_proxy,omitempty"`
	// HTTPSProxy is the HTTPS proxy to use for outbound connections
	HTTPSProxy string `json:"https_proxy,omitempty"`
	// NoProxy is the list of domains to not use the proxy for
	NoProxy []string `json:"no_proxy,omitempty"`
	// VerifySSL is a flag to enable/disable SSL verification
	VerifySSL bool `json:"verify_ssl,omitempty"`
}

// Certificate is the struct for the ssl certificate to generate/renew
type Certificate struct {
	// ACMEEndpoint is the endpoint for the ACME server
	ACMEEndpoint string `yaml:"acme_endpoint"`
	// AuthType is the type of authentication for the ACME server, options are "email"
	AuthType string `yaml:"auth_type"`
	// Email is the email address used when registering with the ACME endpoint
	Email string `yaml:"email"`
	// Domains is a list of domains to generate a certificate for
	Domains []string `yaml:"domains"`
	// SaveType is the type of data that will be stored in the save path, options are "pem-pair" and "haproxy"
	SaveType string `yaml:"save_type"`
	// SavePath is the directory where the files generated will be saved
	// If the directory does not exist, it will be created, as will a .old directory
	// The files saved will be named after the domain name and .crt and optionally the .key file as well if using pem-pair
	SavePath string `yaml:"save_path"`
	// RestartCmd is the command that will be run after the certificate is generated or renewed
	RestartCmd string `yaml:"restart_cmd,omitempty"`
	// RenewDays is the number of days before the certificate expires that it will be renewed
	RenewDays int `yaml:"renew_days,omitempty"`
	// RequestOptions is the list of options that are used when requesting the certificate
	RequestOptions RequestOptions `yaml:"request_options,omitempty"`
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
