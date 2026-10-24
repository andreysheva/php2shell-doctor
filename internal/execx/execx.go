// Package execx runs external commands with hard timeouts and capture,
// so a hung binary or container CLI can never stall a scan.
package execx

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// Result captures a finished command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Run executes name with args, killing it after timeout.
func Run(timeout time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		}
		res.Err = err
	}
	return res
}

// LookPath reports whether name resolves on PATH.
func LookPath(name string) (string, bool) {
	p, err := exec.LookPath(name)
	if err != nil || p == "" {
		return "", false
	}
	return p, true
}
