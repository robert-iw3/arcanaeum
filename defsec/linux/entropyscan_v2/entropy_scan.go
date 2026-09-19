// entropy_scan_v2.go, modified from sandflysecurity
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	constVersion   = "1.1.3"
	constProcDir   = "/proc"
	constDelimiter = ","
	logFile        = "/var/log/entropy_scan.log"
	ConstMinPID    = 1
	ConstMaxPID    = 65535
)

func main() {
	filePath := flag.String("file", "", "Path to a single file to analyze")
	dirPath := flag.String("dir", "", "Directory to scan")
	entropyMaxVal := flag.Float64("entropy", 0, "Show files with entropy >= this value (0.0-8.0)")
	elfOnly := flag.Bool("elf", false, "Only check ELF executables")
	procOnly := flag.Bool("proc", false, "Check running processes")
	csvOutput := flag.Bool("csv", false, "Output in CSV format")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	logFilePath := flag.String("log", logFile, "Log file path")
	logStdout := flag.Bool("log-stdout", false, "Log to stdout instead of file")
	version := flag.Bool("version", false, "Show version and exit")
	delim := flag.String("delim", constDelimiter, "Change the default delimiter for CSV files")
	flag.Parse()

	// Validate delimiter
	if *csvOutput && *delim == "" {
		log.Fatal("Delimiter cannot be empty when -csv is used")
	}

	// Setup logging
	if *logStdout {
		log.SetOutput(os.Stdout)
	} else {
		f, err := os.OpenFile(*logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", *logFilePath, err)
			os.Exit(1)
		}
		defer f.Close()
		log.SetOutput(f)
	}
	log.Printf("Starting entropy_scan v%s", constVersion)

	if *version {
		fmt.Printf("sandfly-entropyscan Version %s\n", constVersion)
		fmt.Printf("Copyright (c) 2019-2025 Sandfly Security\n\n")
		os.Exit(0)
	}

	if *entropyMaxVal > 8 || *entropyMaxVal < 0 {
		log.Fatalf("Entropy value must be between 0.0 and 8.0, got %.2f", *entropyMaxVal)
	}

	// Validate paths
	if *filePath != "" {
		if !filepath.IsAbs(*filePath) {
			log.Fatalf("File path must be absolute: %s", *filePath)
		}
	}
	if *dirPath != "" {
		if !filepath.IsAbs(*dirPath) {
			log.Fatalf("Directory path must be absolute: %s", *dirPath)
		}
	}

	var results []FileInfo
	var wg sync.WaitGroup
	var mu sync.Mutex
	fileChan := make(chan string, 100)

	// Dynamic worker pool based on CPU count
	workerCount := runtime.NumCPU() * 2
	if workerCount < 4 {
		workerCount = 4 // Minimum workers
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				info, err := AnalyzeFile(path)
				if err != nil {
					log.Printf("Error processing %s: %v", path, err)
					continue
				}
				if info.Entropy >= *entropyMaxVal && (!*elfOnly || info.IsElf) {
					mu.Lock()
					results = append(results, info)
					mu.Unlock()
				}
			}
		}()
	}

	procDir := constProcDir
	if os.Getenv("HOST_PROC") != "" {
		procDir = os.Getenv("HOST_PROC") // Support host process scanning
	}

	if *procOnly {
		if os.Geteuid() != 0 {
			log.Fatalf("Process scanning requires root privileges")
		}
		entries, err := os.ReadDir(procDir)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", procDir, err)
		}
		for _, entry := range entries {
			if !entry.Type().IsDir() {
				continue // Skip non-directories
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid < ConstMinPID || pid > ConstMaxPID {
				continue
			}
			path := filepath.Join(procDir, entry.Name(), "exe")
			fileChan <- path
		}
	} else if *filePath != "" {
		fileChan <- *filePath
	} else if *dirPath != "" {
		err := filepath.Walk(*dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("Error accessing %s: %v", path, err)
				return nil
			}
			if info.Mode().IsRegular() {
				fileChan <- path
			}
			return nil
		})
		if err != nil {
			log.Printf("Error walking %s: %v", *dirPath, err)
		}
	} else {
		log.Fatal("Must specify -file, -dir, or -proc")
	}

	close(fileChan)
	wg.Wait()

	if *jsonOutput {
		output := map[string]interface{}{
			"version":      constVersion,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"files":        results,
			"arguments":    os.Args[1:],
			"worker_count": workerCount,
		}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		for _, info := range results {
			if *csvOutput {
				fmt.Printf("%s%s%s%s%.2f%s%v%s%s%s%s%s%s%s%s\n",
					info.Name, *delim, info.Path, *delim, info.Entropy, *delim, info.IsElf,
					*delim, info.Hashes.MD5, *delim, info.Hashes.SHA1,
					*delim, info.Hashes.SHA256, *delim, info.Hashes.SHA512)
			} else {
				fmt.Printf("File: %s\n", info.Name)
				fmt.Printf("  Path: %s\n", info.Path)
				fmt.Printf("  Entropy: %.2f\n", info.Entropy)
				fmt.Printf("  ELF: %v\n", info.IsElf)
				fmt.Printf("  Size: %d bytes\n", info.Size)
				fmt.Printf("  MTime: %s\n", time.Unix(info.MTime, 0).UTC())
				fmt.Printf("  Mode: %s\n", info.Mode)
				fmt.Printf("  MD5: %s\n", info.Hashes.MD5)
				fmt.Printf("  SHA1: %s\n", info.Hashes.SHA1)
				fmt.Printf("  SHA256: %s\n", info.Hashes.SHA256)
				fmt.Printf("  SHA512: %s\n", info.Hashes.SHA512)
				fmt.Println()
			}
		}
		log.Printf("Found %d files with entropy >= %.2f", len(results), *entropyMaxVal)
	}
}