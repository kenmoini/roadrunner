package roadrunner

import (
	"flag"
	"fmt"
	"os"

	"github.com/kenmoini/roadrunner/internal/logging"
	"gopkg.in/yaml.v2"
)

// Entrypoint is the entry point for the roadrunner application, keeps things small and tidy
func Entrypoint() {
	PreflightSetup()
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
	logging.CheckAndFail(err, "Failed to open config file")
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
