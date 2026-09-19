# Decloak data hidden by a Linux stealth rootkit

This utility helps investigate a host for signs of an active Linux stealth rootkit that may
be hiding data in critical files. It does this by reading in a file using standard file I/O
operations and then doing the same using memory mapped I/O to see if the number of bytes
read are identical.

Any differences detected will generate an alert. Plus, you will see the hidden data
decloaked to instantly see if it is suspicious or not. This utility will work against many
common Loadable Kernel Module (LKM) stealth rootkits that use data hiding techniques.

## Linux Loadable Kernel Module Stealth Rootkit File Hiding Tactics

Loadable Kernel Module rootkits on Linux use a variety of tactics to hide. One method is to
hide processes which can be decloaked using our utility process_decloak. The other
is to hide data inside critical start-up scripts so it can maintain persistence between
reboots but not be seen by investigators when running.

For instance the files below are commonly targeted to hide data as they are used to insert
kernel modules upon system boot. Or, these files can be used to insert malicious libraries
to intercept system calls in libc, etc. to alter data to callers:

```text
/etc/modules
/etc/ld.so.conf
```

Also directories for module loading on boot such as:

```text
/etc/modules-load.d
/etc/init.d
/etc/rc*.d
/etc/systemd
```

Many more files can also be used for this purpose and often are hidden under /etc as part
of system init scripts.

## Stealth Rootkit Hiding Method

Most LKM rootkits generally accomplish data hiding by hooking common system calls for file
read operations. They will use a special set of tags to mark data to hide. Between the tags
the malicious data will be inserted. When the rootkit sees the start tag it simply does not
show any data present until the end tag is read. By doing this the rootkit can effectively
hide from discovery using common command line tools and even editors on Linux.

For instance, a modified file may have tags inserted like this:

```bash
# malicious content below
#<lkm_tag>
malicious_module
#</lkm_tag>
```

Anything between the *<lkm_tag>* and *</lkm_tag>* will be masked (along with the tags
themselves) when you use tools like cat, echo, vi and so on. It simply won't be shown.

## Detecting LKM rootkits

It is one thing to convince the kernel to hide data, but something else entirely to get
the file system to agree with it. In fact we know the data is there on the file system
and we just need to bypass the hooked calls to see if we can get it to reveal itself. We'll
accomplish this using memory mapped (mmap) file I/O instead of standard file I/O. LKM
rootkits generally do not intercept mmap file I/O which is a significantly harder and
riskier thing to do.

We will read the file using standard system calls, then we read the file using mmap system
calls in a simple Python script. We then compare the two results. If the results show the
same number of bytes the system is likely clean. However if the two results do not match
then data is being hidden and we will use the mmap I/O to show the data difference and
decloak the data it saw that was different.

## Usage

Simply execute the python script on the system in question and the answer will come forth.

```bash
pip install termcolor

VER=1_2

# analyze a single file
python3 ./file_decloak_${VER}.py -f <file_to_investigate>

# analyze multiple files with verbosity
python3 file_decloak_${VER}.py -f /etc/modules -f /etc/passwd -v

# save cloaked data to a file
python3 file_decloak_${VER}.py -f /etc/modules -o cloaked_data.txt
```

Below we find a system with cloaked data under /etc/modules.

```bash
python3 ./file_decloak_${VER}.py -f /etc/modules


**************************************
File contents with standard I/O
**************************************


# /etc/modules: kernel modules to load at boot time.
#
# This file contains the names of kernel modules that should be loaded
# at boot time, one per line. Lines beginning with "#" are ignored.

# malicious content below



**************************************
File contents with memory mapped I/O
**************************************


# /etc/modules: kernel modules to load at boot time.
#
# This file contains the names of kernel modules that should be loaded
# at boot time, one per line. Lines beginning with "#" are ignored.

# malicious content below
#<reptile>
malicious_module
#</reptile>



Standard IO file size bytes:  222
MMAP IO file size bytes:  260

********************************************************************************************
ALERT: File sizes do not match. File has cloaked data. Check contents above for hidden data.
********************************************************************************************
```

