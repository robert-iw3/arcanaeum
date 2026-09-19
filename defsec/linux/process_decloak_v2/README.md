# What is process_decloak?

`process_decloak` is a utility to quickly scan for Linux Process IDs (PIDs) that
are hidden by common and not-so-common loadable kernel module stealth rootkits and decloak them so
they are visible.

## Features

* Written in Golang and is portable across multiple architectures with no modifications.
* Standalone binary requires no dependencies and can be used instantly without loading any libraries.
* Not affected by ld_preload style rootkits or tampered shared libraries on suspect hosts.
* Works against LKM rootkits such as Diamorphine, Reptile and variants.
* Very lightweight and will not hook into kernel or cause system instability.

## How Do I Use This?

Usage of `process_decloak`:

Simply build and run `process_decloak` on the command line. Hidden PIDs will be shown if
found.

## Examples

When run, the program will show all clean or PIDs that are suspicious:

## Build
```bash
sudo podman build -t decloak .

sudo podman run -it --name decloak --privileged -d decloak
```

## Clean System

```bash
sudo podman exec decloak process_decloak
process_decloak Version 1.0

Decloaking hidden Process IDs (PIDS) on Linux host.
No hidden PIDs found.
```

## Reptile style LKM stealth rootkit

```bash
sudo podman exec decloak process_decloak
process_decloak Version 1.0

Decloaking hidden Process IDs (PIDS) on Linux host.
Found hidden PID: 11468 with name: reptile_hidden
Found hidden PID: 15070 with name: reptile_shell
```

## Diamorphine style LKM stealth rootkit

```bash
sudo podman exec decloak process_decloak
process_decloak Version 1.0

Decloaking hidden Process IDs (PIDS) on Linux host.
Found hidden PID: 7171 with name: diamorphine_hid
```


## Basic Build

On the system architecture you want to compile for, copy the sources under your Golang src directory and run:

`go build process_decloak`

## Build Scripts

There are a some basic build scripts that build for various platforms. You can use these to build or
modify to suit. For Incident Responders, it might be useful to keep pre-compiled binaries ready to
go on your investigation box.

`build_linux_adm64.sh` - Build for AMD64/Intel 64 bit architecture.

`build_linux_arm64.sh` - Build for Arm 64 bit archtecture.

## False Positives

It's possible to flag a legitimate PID that is not actually cloaked. You will need to manually
investigate the /proc/PID directory to check if it is legitimate. Please report false positives to
us if you find them.

## Teardown
```bash
sudo podman stop decloak
sudo podman system prune -f
```