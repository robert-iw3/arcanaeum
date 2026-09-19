# Entropy Scan

`entropy_scan` is a utility to quickly scan files or running processes and report on their entropy (measure
of randomness) and if they are a Linux/Unix ELF type executable. Some malware for Linux is packed or encrypted and
shows very high entropy. This tool can quickly find high entropy executable files and processes which often are
malicious.

## Features

* Written in Golang and is portable across multiple architectures with no modifications.
* Standalone binary requires no dependencies and can be used instanly without loading any libraries on suspect machines.
* Not affected by LD_PRELOAD style rootkits that are cloaking files.
* Built-in PID busting to find hidden/cloaked processes from certain types of Loadable Kernel Module (LKM) rootkits.
* Generates entropy and also MD5, SHA1, SHA256 and SHA512 hash values of files.
* Can be used in scanning scripts to find problems automatically.
* Can be used by incident responders to quickly scan and zero in on potential malware on a Linux host.

## Why Scan for Entropy?

Entropy is a measure of randomness. For binary data 0.0 is not-random and 8.0 is perfectly random. Good crypto looks
like random white noise and will be near 8.0. Good compression removes redundant data making it appear more random
than if it was uncompressed and usually will be 7.7 or above.

A lot of malware executables are packed to avoid detection and make reverse engineering harder. Most standard Linux
binaries are not packed because they aren't trying to hide what they are. Searching for high entropy files is a good
way to find programs that could be malicious just by having these two attributes of high entropy and executable.

## How Do I Use This?

Usage of `entropy_scan`:

`  -csv`
    	output results in CSV format (filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)

`  -delim`
		change the default delimiter for CSV files of "," to one of your choosing ("|", etc.)

`  -dir string`
    	directory name to analyze

`  -file string`
    	full path to a single file to analyze

`  -proc`
		check running processes (defaults to ELF only check)

`  -elf`
    	only check ELF executables

`  -entropy float`
    	show any file/process with entropy greater than or equal to this value (0.0 min - 8.0 max, defaults 0 to show all files)

`   -version`
    	show version and exit

### Prerequisites
---

Podman: Install Podman on your system (e.g., sudo apt install podman or sudo dnf install podman on Linux).

Python 3.6+: Required to run the script.

Go 1.23+: Needed to build the Go application (included in the container build process).

Root Privileges: Required for Podman commands and host process scanning (--host-proc or -proc).

```console
.
├── Dockerfile
├── entropy_scan.go
├── fileutils.go
├── go.mod
├── podman_entropy_scan.py
```

## Examples

```bash
# via python

sudo python3 podman_entropy_scan.py [options]
```

Options

`--build`: Build the Podman image before running (required for first run or after code changes).

`--no-recreate`: Reuse an existing container if available, instead of removing and recreating it.

`--container-name <name>`: Specify the container name (default: `entropyscan`).

`-csv`: Output results in CSV format (filename, path, entropy, elf_file, MD5, SHA1, SHA256, SHA512).

`-delim <delimiter>`: Set the CSV delimiter (default: `,`).

`-dir <path>`: Host directory to analyze (mounted to `/scan` in the container; must be readable, not a symlink).

`-file <path>`: Host file to analyze (directory of file mounted to `/scan`; must be readable, not a symlink).

`-proc`: Scan running processes inside the container (defaults to ELF only; requires `--privileged`).

`--host-proc`: Scan running processes on the host (mounts /proc to /host_proc; requires `--privileged`).

`-elf`: Only check ELF executables.

`-entropy <value>`: Show files/processes with entropy >= this value (0.0–8.0, default: 0.0).

`-json`: Output results in JSON format.

`-version`: Show the entropy_scan version and exit.

`-o`, `--output <file>`: Save output to the specified file.

`--append`: Append to the output file instead of overwriting (used with `-o`).

`--timeout <seconds>`: Set timeout for scan execution (default: 300 seconds).

`--log <file>`: Log script actions to the specified file (default: stderr).

`--verbose`: Enable verbose logging for debugging.

`--summarize`: Summarize JSON output (e.g., count of high-entropy files; used with `-json`).

---

1. ***Build and scan a directory for ELF executables:***

	`sudo python3 podman_entropy_scan.py --build -dir /tmp -elf`

	Builds the image and scans /tmp for ELF executables.

2. ***Scan a directory for high-entropy ELF files with output to a file:***

	`sudo python3 podman_entropy_scan.py -dir /var/www -elf -entropy 7.7 -o results.txt`

	Scans `/var/www` for ELF files with entropy >= 7.7 and saves output to `results.txt`.

3. ***Scan host processes in CSV format:***

	`sudo python3 podman_entropy_scan.py --host-proc -csv`

	Scans host processes and outputs in CSV format.

4. ***Scan a single file with JSON output and summary:***

	`sudo python3 podman_entropy_scan.py -file /tmp/suspicious_file -json --summarize`

	Scans the file, outputs in JSON, and prepends a summary.

5. ***Scan a directory with custom CSV delimiter and append to file:***

	`sudo python3 podman_entropy_scan.py -dir /bin -csv -delim "|" -o my_scan.csv --append`

	Scans `/bin`, outputs in CSV with `|` delimiter, and appends to `my_scan.csv`.

6. ***Reuse existing container and scan processes with timeout:***

	`sudo python3 podman_entropy_scan.py --no-recreate -proc -entropy 7.7 --timeout 600`

	Reuses the container, scans container processes with entropy >= 7.7, with a 10-minute timeout.

7. ***Show version with logging to a file:***

	`sudo python3 podman_entropy_scan.py -version --log scan.log`

	Displays the `entropy_scan` version and logs actions to `scan.log`.

Notes

The `--privileged` flag is only used for `-proc` or `--host-proc` to minimize security risks.

The container is removed and recreated unless `--no-recreate` is specified.

Volume mounts (`-dir` or `-file`) map the host path to `/scan` in the container.

Host process scanning (`--host-proc`) mounts `/proc` to `/host_proc` for access.

Logs are written to stderr by default or to a file with `--log`.

Use `--verbose` for detailed logs during debugging.

The `--summarize` flag provides a summary for JSON output, showing the number of files scanned, high-entropy files (>=7.0), and ELF files.

## Examples with using podman

```bash
sudo podman build -t entropyscan .

sudo podman run -it --name entropyscan \
	-v <THE_VOLUME_TO_SCAN>:/scan \
	--privileged \
	-d entropyscan
```

Search for any file that is executable under /tmp:

`sudo podman exec entropyscan entropy_scan -dir /scan -elf`

Search for high entropy (7.7 and higher) executables (often packed or encrypted) under /var/www:

`sudo podman exec entropyscan entropy_scan -dir /scan -elf -entropy 7.7`

Generates entropy and cryptographic hashes of all running processes in CSV format:

`sudo podman exec entropyscan entropy_scan -proc -csv`

Search for any process with an entropy higher than 7.7 indicating it is likely packed or encrypted:

`sudo podman exec entropyscan entropy_scan -proc -entropy 7.7`

Generate entropy and cryptographic hash values of all files under /bin and output to CSV format (for instance to save and compare hashes):

`sudo podman exec entropyscan entropy_scan -dir /scan -csv >> my_scan.csv`

Scan a directory for all files (ELF or not) with entropy greater than 7.7:
(potentially large list of files that are compressed, png, jpg, object files, etc.)

`sudo podman exec entropyscan entropy_scan -dir /scan -entropy 7.7`

Quickly check a file and generate entropy, cryptographic hashes and show if it is executable:

`sudo podman exec entropyscan entropy_scan -file /scan/suspicious_file`

# Use Cases

Do spot checks on systems you think have a malware issue. Or you can automate the scan so you will get an output
if we find something show up that is high entropy in a place you didn't expect. Or simply flag any executable ELF type
file that is somewhere strange (e.g. hanging out in /tmp or under a user's HTML directory). For instance:

Did a high entropy binary show up under the system /var/www directory? Could be someone put a malware dropper
on your website:

`sudo podman exec entropyscan entropy_scan -dir /scan -elf -entropy 7.7`

Setup a cron task to scan your /tmp, /var/tmp, and /dev/shm directories for any kind of executable file whether it's
high entropy or not. Executable files under tmp directories can frequently be a malware dropper.

`sudo podman exec entropyscan entropy_scan -dir /scan -elf`

`sudo podman exec entropyscan entropy_scan -dir /scan -elf`

`sudo podman exec entropyscan entropy_scan -dir /scan -elf`

Setup another cron or automated security sweep to spot check your systems for highly compressed or encrypted binaries that
are running:

`sudo podman exec entropyscan entropy_scan -proc -entropy 7.7`

# Build

`go build`

* Run the binary with your options:

`./entropy_scan`

## Build Scripts

There are a some basic build scripts that build for various platforms. You can use these to build or modify to suit.
For Incident Responders, it might be useful to keep pre-compiled binaries ready to go on your investigation box.

`build.sh` - Build for current OS you're running on when you execute it.

# ELF Detection

We use a simple method for seeing if a file may be an executable ELF type. We can spot ELF format files for
multiple platforms. Even if malware has Intel/AMD, MIPS and Arm dropper binaries we will still be able to spot all of
them.

# False Positives

It's possible to flag a legitimate binary that has a high entropy because of how it was compiled, or because
it was packed for legitimate reasons. Other files like .zip, .gz, .png, .jpg and such also have very high entropy
because they are compressed formats. Compression removes redundancy in a file which makes it appear to be more
random and has higher entropy.

On Linux, you may find some kinds of libraries (.so files) get flagged if you scan library directories.

However, it is our experience that executable binaries that also have high entropy are often malicious. This is
especially true if you find them in areas where executables normally shouldn't be (such as again `tmp` or `html`
directories).

# Performance

The entropy calculation requires reading in all the bytes of the file and tallying them up to get a final number. It
can use a lot of CPU and disk I/O, especially on very large file systems or very large files. The program has an
internal limit where it won't calculate entropy on any file over 2GB, nor will it try to calculate entropy on any
file that is not a regular file type (e.g. won't try to calculate entropy on devices like `/dev/zero`).

Then we calculate MD5, SHA1, SHA256 and SHA512 hashes. Each of these requires going over the file as well. It's
reasonable speed on modern systems, but if you are crawling a very large file system it can take some time to
complete.

If you tell the program to only look at ELF files, then the entropy/hash calculations won't happen unless it is an
ELF type and this will save a lot of time (e.g. it will ignore massive database files that aren't executable).

If you want to automate this program, it's best to not have it crawl the entire root file system unless you want
that specifically. A targeted approach will be faster and more useful for spot checks. Also, use the ELF flag as that
will drastically reduce search times by only processing executable file types.

# Incident Response

For incident responders, running `entropy_scan` against the entire top-level "/" directory may be a good idea just
to quickly get a list of likely packed candidates to investigate. This will spike CPU and disk I/O. However, you probably
don't care at that point since the box has been mining cryptocurrency for 598 hours anyway by the time the admins
noticed.

Again, use the ELF flag to get to the likely problem candidate executables and ignore the noise.

# Testing

There is a script called `scripts/testfiles.sh` that will make two files. One will be full of random data and one will not be
random at all. When you run the script it will make the files and run `entropy_scan` in executable detection mode.
You should see two files. One with very high entropy (at or near 8.0) and one full of non-random data that should
be at 0.00 for low entropy. Example:

`./testfiles.sh`

Creating high entropy random executable-like file in current directory.

Creating low entropy executable-like file in current directory.

high.entropy.test, entropy: 8.00, elf: true

low.entropy.test, entropy: 0.00, elf: true

You can also load up the `upx` utility and compress an executable and see what values it returns.

## Teardown
```bash
sudo podman stop entropyscan
sudo podman system prune -f
```

