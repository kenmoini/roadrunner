package helpers

func DisplayHelp() {
	// Display help
	const message = `Roadrunner is a simple tool to help you manage your certificates and keys.

Usage:
  roadrunner -config <path to config file>`

	// Print the message
	println(message)
}

func AppendSlash(path string) string {
	if path[len(path)-1:] != "/" {
		path = path + "/"
	}
	return path
}
