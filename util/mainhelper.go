package util

import (
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

var startupTime = time.Now()

// MainStart is an opinionated startup - configures build in components.
func MainStart() func(string) string {
	jsh := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
	})
	slog.SetDefault(slog.New(jsh))
	return GetString
}

// Main config helper - base implementation for minimal deps CLI.
//
// Larger binaries should use viper - which provides support for:
// - ini, json, yaml, java properties
// - remote providers (with encryption) - built in etcd3, consul, firestore
func GetString(key string) string {
	return os.Getenv(key)
}

func MainEnd() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var cmd string
	var argv []string
	posArgs := os.Args
	if len(posArgs) == 1 {
		for {
			sig := <-sigCh

			slog.Info("Exit",
				"sig", sig,
				"running", time.Since(startupTime))

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