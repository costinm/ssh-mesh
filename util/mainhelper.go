package util

import (
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Main helper provides boilerplate utilities for running a main()
// and loading initial config.

var startupTime = time.Now()

// FindConfig is a simple loader for a config file.
func FindConfig(base string, s string) []byte {

	basecfg := os.Getenv(base)
	if basecfg != "" {
		return []byte(basecfg)
	}

	// Explicitly set
	//cfgDir := os.Getenv("CFG_DIR")
	//if cfgDir != "" {
	//	fb, err := os.ReadFile(cfgDir + base + ".json")
	//	if err == nil {
	//		return fb
	//	}
	//}

	fb, err := os.ReadFile("./" + base + s)
	if err == nil {
		return fb
	}

	fb, err = os.ReadFile("/" + base + "/" + base + s)
	if err == nil {
		return fb
	}

	//fb, err = os.ReadFile(os.Getenv("HOME") + "/.config/" +
	//	base + "/" + base + ".json")
	//if err == nil {
	//	return fb
	//}

	// Also look in the .ssh directory - this is mainly for secrets.
	fb, err = os.ReadFile(os.Getenv("HOME") + "/.ssh/" + base + s)
	if err == nil {
		return fb
	}

	return nil
}

// MainStart is an opinionated startup - configures build in components.
// 'base' is the name of the config - for example 'mds'
// If it is set as an environment variable - it is expected to be a json config.
// Otherwise, a file /$base/$base.json or ./$base.json will be loaded.
// Other env variables of type string may be merged into the config.
//
// - Will init slog with a json handler
//
// Larger binaries should use viper - which provides support for:
// - ini, json, yaml, java properties
// - remote providers (with encryption) - built in etcd3, consul, firestore
func MainStart(base string, out interface{}) {
	basecfg := FindConfig(base, ".json")
	if basecfg != nil {
		json.Unmarshal([]byte(basecfg), out)
	}

	// Quick hack to load environment variables into the config struct.
	envl := os.Environ()
	envm := map[string]string{}
	for _, k := range envl {
		kv := strings.SplitN(k, "=", 2)
		if len(kv) == 2 {
			envm[kv[0]] = kv[1]
		}
	}
	envb, _ := json.Marshal(envm)

	json.Unmarshal(envb, out)
}

// Main config helper - base implementation for minimal deps CLI.
//
// Larger binaries should use viper - which provides support for:
// - ini, json, yaml, java properties
// - remote providers (with encryption) - built in etcd3, consul, firestore
func GetString(key string) string {
	return os.Getenv(key)
}

// MainEnd should be the last call in main(). The app is expected to get all the config
// from file or env variables - if the command line arguments are not empty: exec the remaining
// and wait to complete - else wait for a signal.
func MainEnd() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var cmd string
	var argv []string

	posArgs := os.Args
	if len(posArgs) == 1 {
		for {
			sig := <-sigCh

			slog.Info("Exit", "sig", sig, "running", time.Since(startupTime))

			d := GetString("DRAIN_TIMEOUT")
			if d == "" {
				d = "1"
			}
			di, _ := strconv.Atoi(d)
			time.AfterFunc(time.Second*time.Duration(di), func() {
				os.Exit(0)
			})
			// Testing force exit timing
			// return
		}
	}

	// If it has extra args, exec the command
	if len(posArgs) > 2 {
		cmd, argv = posArgs[1], posArgs[2:]
	} else {
		cmd = posArgs[1]
	}
	c := exec.Command(cmd, argv...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Env = os.Environ()

	if err := c.Start(); err != nil {
		slog.Error("failed to start subprocess", "cmd", cmd, "args", argv, "err", err)
		os.Exit(c.ProcessState.ExitCode())
	}

	go func() {
		sig := <-sigCh
		if err := c.Process.Signal(sig); err != nil {
			log.Printf("failed to signal process: %v", err)
		}
	}()

	if err := c.Wait(); err != nil {
		if v, ok := err.(*exec.ExitError); ok {
			ec := v.ExitCode()
			os.Exit(ec)
		}
	}

}
