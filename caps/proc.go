package caps

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type ProcessPermission interface {
	Capability
}

type procImpl struct {
	capabilityMarker
	commands map[string]bool
	valid    bool
}

func RequestExecPermission[T any](
	commands []string,
	op func(ProcessPermission) (T, error),
) (T, error) {
	_, span := StartSpan(context.Background(), "caps.Process.Request",
		attribute.StringSlice("commands", commands),
	)
	defer EndSpan(span, nil)
	RecordRequest(context.Background(), "process")

	cmdSet := make(map[string]bool, len(commands))
	for _, c := range commands {
		cmdSet[c] = true
	}
	p := &procImpl{
		commands: cmdSet,
		valid:    true,
	}
	defer func() { p.valid = false }()
	result, err := op(p)
	EndSpan(span, err)
	return result, err
}

func (p *procImpl) validate(command string) error {
	if !p.valid {
		return fmt.Errorf("cap: ProcessPermission used outside its scope")
	}
	if len(p.commands) == 0 {
		return fmt.Errorf("cap: no commands permitted")
	}
	if !p.commands[command] {
		allowed := make([]string, 0, len(p.commands))
		for c := range p.commands {
			allowed = append(allowed, c)
		}
		return fmt.Errorf("cap: command %q not in allowlist %v", command, allowed)
	}
	return nil
}

func Exec(perm ProcessPermission, command string, args []string, opts ExecOptions) (ProcessResult, error) {
	_, span := StartSpan(context.Background(), "caps.Process.Exec",
		attribute.String("command", command),
		attribute.StringSlice("args", args),
	)

	p, ok := perm.(*procImpl)
	if !ok {
		EndSpan(span, fmt.Errorf("cap: invalid ProcessPermission"))
		RecordOperation(context.Background(), "exec", fmt.Errorf("cap: invalid ProcessPermission"))
		return ProcessResult{}, fmt.Errorf("cap: invalid ProcessPermission")
	}
	if err := p.validate(command); err != nil {
		EndSpan(span, err)
		RecordOperation(context.Background(), "exec", err)
		return ProcessResult{}, err
	}
	ctx := p
	if opts.TimeoutMs > 0 {
		var cancel func()
		// We use a simple approach: just pass timeout via cmd
		_ = cancel
	}
	cmd := exec.Command(command, args...)
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	var runErr error
	if opts.TimeoutMs > 0 {
		timer := time.After(time.Duration(opts.TimeoutMs) * time.Millisecond)
		select {
		case runErr = <-done:
		case <-timer:
			_ = cmd.Process.Kill()
			runErr = fmt.Errorf("cap: command timed out after %dms", opts.TimeoutMs)
		}
	} else {
		runErr = <-done
	}
	_ = ctx

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			EndSpan(span, runErr)
			RecordOperation(context.Background(), "exec", runErr)
			return ProcessResult{}, runErr
		}
	}

	EndSpan(span, nil)
	RecordOperation(context.Background(), "exec", nil)
	return ProcessResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

func ExecOutput(perm ProcessPermission, command string, args []string) (string, error) {
	result, err := Exec(perm, command, args, ExecOptions{})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Stdout), nil
}
