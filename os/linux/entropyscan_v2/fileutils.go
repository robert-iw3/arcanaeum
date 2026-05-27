// fileutils.go, modified from sandflysecurity
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Constants
const (
	MaxFileSize     = 2147483648 // 2GB
	MaxEntropyChunk = 256000     // 256KB
	MagicNumRead    = 4
	MagicNumElf     = "\x7FELF"
)

// FileInfo holds file metadata
type FileInfo struct {
	Path       string  `json:"path"`
	Name       string  `json:"name"`
	Entropy    float64 `json:"entropy"`
	IsElf      bool    `json:"is_elf"`
	Size       int64   `json:"size"`
	MTime      int64   `json:"mtime"`
	Mode       string  `json:"mode"`
	Hashes     Hashes  `json:"hashes"`
}

// Hashes holds cryptographic hashes
type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

// IsElfType checks if a file is a Linux Elf executable
func IsElfType(path string) (bool, error) {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") || path == "" {
		return false, fmt.Errorf("invalid path: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("cannot open %s: %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("cannot stat %s: %v", path, err)
	}
	if !fStat.Mode().IsRegular() || fStat.Size() < MagicNumRead {
		return false, nil
	}

	var header [MagicNumRead]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return false, fmt.Errorf("cannot read header of %s: %v", path, err)
	}

	return bytes.Equal(header[:], []byte(MagicNumElf)), nil
}

// AnalyzeFile computes entropy and hashes in a single pass
func AnalyzeFile(path string) (FileInfo, error) {
	var info FileInfo
	if !filepath.IsAbs(path) || strings.Contains(path, "..") || path == "" {
		return info, fmt.Errorf("invalid path: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return info, fmt.Errorf("cannot open %s: %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return info, fmt.Errorf("cannot stat %s: %v", path, err)
	}
	if !fStat.Mode().IsRegular() {
		return info, nil
	}
	if fStat.Size() > MaxFileSize {
		return info, fmt.Errorf("file size (%d) exceeds maximum (%d) for %s", fStat.Size(), MaxFileSize, path)
	}

	info.Path = path
	info.Name = filepath.Base(path)
	info.Size = fStat.Size()
	info.MTime = fStat.ModTime().Unix()
	info.Mode = fStat.Mode().String()

	// Check ELF type
	info.IsElf, err = IsElfType(path)
	if err != nil {
		return info, err
	}

	// Single-pass reading for entropy and hashes
	if fStat.Size() == 0 {
		return info, nil
	}

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	byteCounts := make([]int, 256)
	data := make([]byte, MaxEntropyChunk)

	for {
		n, err := f.Read(data[:cap(data)])
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, fmt.Errorf("failed to read %s: %v", path, err)
		}
		data = data[:n] // Adjust slice to actual bytes read

		// Update hashes
		_, _ = md5Hash.Write(data)
		_, _ = sha1Hash.Write(data)
		_, _ = sha256Hash.Write(data)
		_, _ = sha512Hash.Write(data)

		// Update entropy counts
		for _, b := range data {
			byteCounts[b]++
		}
	}

	// Calculate entropy
	var entropy float64
	totalBytes := float64(fStat.Size())
	if totalBytes > 0 {
		for _, count := range byteCounts {
			if count > 0 {
				p := float64(count) / totalBytes
				entropy -= p * math.Log2(p)
			}
		}
	}
	info.Entropy = entropy

	// Set hashes
	info.Hashes.MD5 = hex.EncodeToString(md5Hash.Sum(nil))
	info.Hashes.SHA1 = hex.EncodeToString(sha1Hash.Sum(nil))
	info.Hashes.SHA256 = hex.EncodeToString(sha256Hash.Sum(nil))
	info.Hashes.SHA512 = hex.EncodeToString(sha512Hash.Sum(nil))

	return info, nil
}