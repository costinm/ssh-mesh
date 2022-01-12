package ssh

import "os"

// Get config from env variables, files, URLs

func Conf(keyn, def string) string {
	val := os.Getenv(keyn)
	if val == "" {
		val = def
	}
	return val
}
