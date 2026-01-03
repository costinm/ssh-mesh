package cmd

import (
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Common app boilerplate (also present in meshauth/pkg/appinit)
var startupTime = time.Now()

// WaitEnd should be the last thing in a main() app - will block, waiting for SIGTERM and handle draining.
//
// This will also handle any extra args - interpreting them as a CLI and running the command, allowing
// chaining in docker. Init is using a yaml for config and no CLI.
func WaitEnd() {

	if len(os.Args) == 1 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		//for {
		//sig := <-sigCh

		// d := os.Getenv("DRAIN_TIMEOUT")
		// if d == "" {
		// 	d = "1000"
		// }
		// di, _ := strconv.Atoi(d)

		// slog.Info("Exit", "sig", sig, "running", time.Since(startupTime),
		// 	"drain", di)

		// time.AfterFunc(time.Millisecond*time.Duration(di), func() {
		// 	os.Exit(0)
		// })
		//}
		<-sigCh
		os.Exit(0)
	}

	cmd := os.Args[1]
	var argv []string

	// If it has extra args, exec the command
	if len(os.Args) > 2 {
		argv = os.Args[2:]
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		if err := c.Process.Signal(sig); err != nil {
			slog.Error("failed to signal process", "err", err)
		}
	}()

	if err := c.Wait(); err != nil {
		if v, ok := err.(*exec.ExitError); ok {
			ec := v.ExitCode()
			os.Exit(ec)
		}
	}
}
