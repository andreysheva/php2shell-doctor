package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/andreysheva/php2shell-doctor/internal/execx"
	"github.com/andreysheva/php2shell-doctor/internal/model"
)

// scanProcesses enumerates running PHP-related processes for staleness
// checks: php-fpm masters/workers, apache/httpd with mod_php, php-cgi,
// litespeed and frankenphp.
func scanProcesses() ([]model.ProcessInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return scanProcfs()
	case "darwin":
		return scanPs("auxww")
	case "windows":
		return scanWindowsProcesses()
	}
	return nil, fmt.Errorf("process scan unsupported on %s", runtime.GOOS)
}

func isPHPProcessName(name string) bool {
	n := strings.ToLower(name)
	for _, want := range []string{"php-fpm", "php-fpm:", "php", "httpd", "apache2", "frankenphp", "litespeed", "lshttpd", "php-cgi"} {
		if strings.HasPrefix(n, want) {
			return true
		}
	}
	return false
}

// scanProcfs reads /proc natively (no subprocess): exe symlink, cmdline
// and process start time from stat field 22 (jiffies since boot).
func scanProcfs() ([]model.ProcessInfo, error) {
	var out []model.ProcessInfo
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	btime := bootTime()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, _ := os.Readlink("/proc/" + e.Name() + "/exe")
		cmdBytes, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		cmdline := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		base := filepath.Base(exe)
		if base == "" {
			base = firstField(cmdline)
		}
		if !isPHPProcessName(base) && !strings.Contains(strings.ToLower(cmdline), "php") {
			continue
		}
		started := procStartTime(pid, btime)
		var binMtime time.Time
		if exe != "" {
			if fi, err := os.Stat(exe); err == nil {
				binMtime = fi.ModTime()
			}
		}
		out = append(out, model.ProcessInfo{
			PID: pid, Name: base, ExePath: exe, Cmdline: cmdline,
			Started: started, BinaryMtime: binMtime,
		})
	}
	return out, nil
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func bootTime() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			sec, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			return time.Unix(sec, 0)
		}
	}
	return time.Time{}
}

func procStartTime(pid int, btime time.Time) time.Time {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}
	}
	s := string(b)
	// field 22 (1-based) is starttime; fields after the comm "(...)" part
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return time.Time{}
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 20 {
		return time.Time{}
	}
	jiffies, _ := strconv.ParseFloat(fields[19], 64)
	clk := 100.0 // _SC_CLK_TCK is 100 on every mainstream Linux
	return btime.Add(time.Duration(jiffies / clk * float64(time.Second)))
}

func scanPs(args string) ([]model.ProcessInfo, error) {
	r := execx.Run(15e9, "ps", strings.Fields(args)...)
	if r.Err != nil {
		return nil, fmt.Errorf("ps failed: %v", r.Err)
	}
	var out []model.ProcessInfo
	for i, line := range strings.Split(r.Stdout, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 11 {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		cmd := strings.Join(f[10:], " ")
		base := firstField(cmd)
		if !isPHPProcessName(base) && !strings.Contains(strings.ToLower(cmd), "php") {
			continue
		}
		out = append(out, model.ProcessInfo{PID: pid, Name: base, Cmdline: cmd})
	}
	return out, nil
}

func scanWindowsProcesses() ([]model.ProcessInfo, error) {
	// PowerShell one-liner: no external deps, read-only. ExecutablePath
	// gives the real binary (CommandLine is a rewritten argv such as
	// "php-fpm: pool www" and is not a path).
	ps := `Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'php|httpd|apache|frankenphp|litespeed' } | Select-Object ProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress`
	r := execx.Run(30e9, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if r.Err != nil && r.Stdout == "" {
		return nil, fmt.Errorf("powershell process query failed: %v", r.Err)
	}
	return parsePSCIMIJSON(r.Stdout), nil
}
