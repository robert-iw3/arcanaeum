// updated & improved from sandflysecurity/processutils
package processutils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Constants
const (
	ConstMinPID            = 1
	ConstMaxPID            = 4194304
	ConstHiddenVerifyDelay = 1
	ProcPath              = "/proc"
)

// WorkerCount returns the number of workers used
func WorkerCount() int {
	workerCount := runtime.NumCPU() * 2
	if workerCount < 4 {
		workerCount = 4
	}
	return workerCount
}

// PIDStatus holds process metadata
type PIDStatus struct {
	Name    string `json:"name"`
	Umask   string `json:"umask"`
	State   string `json:"state"`
	Tgid    int    `json:"tgid"`
	Ngid    int    `json:"ngid"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Cmdline string `json:"cmdline"`
	Exe     string `json:"exe"`
}

// DecloakPIDs finds hidden PIDs by scanning /proc and checking for hidden processes
func DecloakPIDs() ([]PIDStatus, error) {
	var hiddenPIDs []PIDStatus
	var wg sync.WaitGroup
	var mu sync.Mutex
	pidChan := make(chan int, 100)

	// Use HOST_PROC environment variable for host process scanning
	procDir := ProcPath
	if os.Getenv("HOST_PROC") != "" {
		procDir = os.Getenv("HOST_PROC")
	}

	// Validate proc path
	if !filepath.IsAbs(procDir) || strings.Contains(procDir, "..") {
		return nil, fmt.Errorf("invalid proc path: %s", procDir)
	}
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("proc filesystem not found at %s", procDir)
	}

	// Read /proc directory for candidate PIDs
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", procDir, err)
	}

	// Start workers
	workerCount := WorkerCount()
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range pidChan {
				hidden, status, err := IsPidHidden(pid, true)
				if err != nil {
					continue
				}
				if hidden {
					mu.Lock()
					hiddenPIDs = append(hiddenPIDs, status)
					mu.Unlock()
				}
			}
		}()
	}

	// Feed PIDs from /proc
	for _, entry := range entries {
		if !entry.Type().IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid >= ConstMinPID && pid <= ConstMaxPID {
			pidChan <- pid
		}
	}
	close(pidChan)
	wg.Wait()

	return hiddenPIDs, nil
}

// IsPidHidden checks if a PID is hidden
func IsPidHidden(pid int, raceVerify bool) (bool, PIDStatus, error) {
	var pidStatus PIDStatus
	if pid < ConstMinPID || pid > ConstMaxPID {
		return false, pidStatus, fmt.Errorf("PID %d must be between %d and %d", pid, ConstMinPID, ConstMaxPID)
	}

	// Use HOST_PROC environment variable
	procDir := ProcPath
	if os.Getenv("HOST_PROC") != "" {
		procDir = os.Getenv("HOST_PROC")
	}

	// Validate path
	pidPath := filepath.Join(procDir, strconv.Itoa(pid))
	if !filepath.IsAbs(pidPath) || strings.Contains(pidPath, "..") {
		return false, pidStatus, fmt.Errorf("invalid PID path: %s", pidPath)
	}

	// Check /proc/[pid]/maps
	maps, err := PidMaps(pid)
	if err != nil || len(maps) == 0 {
		return false, pidStatus, nil
	}

	// Get process status
	pidStatus, err = Status(pid)
	if err != nil {
		return false, pidStatus, nil
	}

	// Check if PID is not a thread
	if pidStatus.PID != pidStatus.Tgid || pidStatus.PID <= 0 {
		return false, pidStatus, nil
	}

	// Check if PID is hidden via lstat
	hidden := false
	if _, err := os.Lstat(pidPath); err != nil {
		hidden = true
	}

	// Check if PID is missing from /proc listing
	if !hidden {
		entries, err := os.ReadDir(procDir)
		if err != nil {
			return false, pidStatus, fmt.Errorf("failed to read %s: %v", procDir, err)
		}
		hidden = true
		for _, entry := range entries {
			if pidStr, err := strconv.Atoi(entry.Name()); err == nil && pidStr == pid {
				hidden = false
				break
			}
		}
	}

	// Re-verify if hidden
	if hidden && raceVerify {
		time.Sleep(time.Second * ConstHiddenVerifyDelay)
		hidden, pidStatus, err = IsPidHidden(pid, false)
	}

	return hidden, pidStatus, err
}

// PidMaps reads /proc/[pid]/maps
func PidMaps(pid int) ([]string, error) {
	if pid < ConstMinPID || pid > ConstMaxPID {
		return nil, fmt.Errorf("PID %d must be between %d and %d", pid, ConstMinPID, ConstMaxPID)
	}

	procDir := ProcPath
	if os.Getenv("HOST_PROC") != "" {
		procDir = os.Getenv("HOST_PROC")
	}

	pidPath := filepath.Join(procDir, strconv.Itoa(pid), "maps")
	f, err := os.Open(pidPath)
	if err != nil {
		return nil, nil // Ignore errors for non-existent PIDs
	}
	defer f.Close()

	var maps []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		maps = append(maps, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading process maps file for PID %d: %v", pid, err)
	}
	return maps, nil
}

// Status reads /proc/[pid]/status and additional metadata
func Status(pid int) (PIDStatus, error) {
	var status PIDStatus
	if pid < ConstMinPID || pid > ConstMaxPID {
		return status, fmt.Errorf("PID %d must be between %d and %d", pid, ConstMinPID, ConstMaxPID)
	}

	procDir := ProcPath
	if os.Getenv("HOST_PROC") != "" {
		procDir = os.Getenv("HOST_PROC")
	}

	// Read status
	statPath := filepath.Join(procDir, strconv.Itoa(pid), "status")
	f, err := os.Open(statPath)
	if err != nil {
		return status, nil // Ignore errors for non-existent PIDs
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineEntry := strings.SplitN(scanner.Text(), ":", 2)
		if len(lineEntry) < 2 {
			continue
		}
		lineData := strings.Fields(lineEntry[1])
		if len(lineData) == 0 {
			continue
		}
		switch lineEntry[0] {
		case "Name":
			status.Name = lineData[0]
		case "Umask":
			status.Umask = lineData[0]
		case "State":
			status.State = lineData[0]
		case "Tgid":
			status.Tgid, err = strconv.Atoi(lineData[0])
			if err != nil {
				return status, fmt.Errorf("cannot convert tgid for PID %d: %v", pid, err)
			}
		case "Ngid":
			status.Ngid, err = strconv.Atoi(lineData[0])
			if err != nil {
				return status, fmt.Errorf("cannot convert ngid for PID %d: %v", pid, err)
			}
		case "Pid":
			status.PID, err = strconv.Atoi(lineData[0])
			if err != nil {
				return status, fmt.Errorf("cannot convert pid for PID %d: %v", pid, err)
			}
		case "PPid":
			status.PPID, err = strconv.Atoi(lineData[0])
			if err != nil {
				return status, fmt.Errorf("cannot convert ppid for PID %d: %v", pid, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return status, fmt.Errorf("error reading status file for PID %d: %v", pid, err)
	}

	// Read cmdline
	cmdlinePath := filepath.Join(procDir, strconv.Itoa(pid), "cmdline")
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		status.Cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
	}

	// Read exe
	exePath := filepath.Join(procDir, strconv.Itoa(pid), "exe")
	if exe, err := os.Readlink(exePath); err == nil {
		status.Exe = exe
	}

	return status, nil
}