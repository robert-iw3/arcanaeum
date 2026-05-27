// updated & improved from sandflysecurity/process_decloak
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sandflysecurity/sandfly-processdecloak/processutils"
)

const (
	constVersion = "1.0.8"
	logFile      = "/var/log/process_decloak.log"
)

func main() {
	// Command-line flags
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	logFilePath := flag.String("log", logFile, "Log file path")
	logStdout := flag.Bool("log-stdout", false, "Log to stdout instead of file")
	flag.Parse()

	// Setup logging
	if *logStdout {
		log.SetOutput(os.Stdout)
	} else {
		if *logFilePath == "" {
			log.Fatalf("Log file path cannot be empty")
		}
		f, err := os.OpenFile(*logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", *logFilePath, err)
			os.Exit(1)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	log.Printf("Starting process_decloak v%s", constVersion)

	hiddenPIDs, err := processutils.DecloakPIDs()
	if err != nil {
		log.Fatalf("Error analyzing PIDs: %v", err)
	}

	if *jsonOutput {
		output := map[string]interface{}{
			"version":      constVersion,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"hidden_pids":  hiddenPIDs,
			"pid_count":    len(hiddenPIDs),
			"arguments":    os.Args[1:],
			"worker_count": processutils.WorkerCount(),
		}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		fmt.Printf("process_decloak Version %s\n", constVersion)
		fmt.Printf("===================================================\n")
		fmt.Printf("Agentless Security for Linux\n\n")
		fmt.Printf("Decloaking hidden Process IDs (PIDs) on Linux host.\n")
		if len(hiddenPIDs) > 0 {
			for _, status := range hiddenPIDs {
				fmt.Printf("Found hidden PID: %d\n", status.PID)
				fmt.Printf("  Name: %s\n", status.Name)
				fmt.Printf("  Cmdline: %s\n", status.Cmdline)
				fmt.Printf("  Exe: %s\n", status.Exe)
				fmt.Printf("  State: %s\n", status.State)
				fmt.Printf("  PPID: %d\n", status.PPID)
				log.Printf("Hidden PID: %d, Name: %s, Cmdline: %s, Exe: %s", status.PID, status.Name, status.Cmdline, status.Exe)
			}
		} else {
			fmt.Printf("No hidden PIDs found.\n")
			log.Printf("No hidden PIDs found")
		}
	}
}