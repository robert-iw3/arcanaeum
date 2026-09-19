#
# A utility to test if a file is hiding cloaked data due to a Loadable Kernel Module (LKM) or
# LD_PRELOAD stealth rootkit on Linux. Simply call the command as follows against a suspect file:
#
# python3 ./file_decloak_ver1.py -f /etc/modules
#
# Any cloaked data will be reported and decloaked so you can see the contents and investigate if
# it is malicious.
#

import getopt
import mmap
import sys
import binascii

VERSION="1.0"

def main():
    filename = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:")
    except getopt.GetoptError:
        print("Illegal option. Valid option is -f")
        sys.exit(-1)

    if len(opts) > 0:
        for opt, arg in opts:
            if opt == '-f':
                filename = arg

    if not filename:
        print("Need to supply filename with -f")
        sys.exit(-1)


    print("\nFile Decloaking Utility - Version {0}".format(VERSION))
    print("=======================================================")
    print("Agentless Security for Linux")

    print("\n\n**************************************")
    print("File contents with standard I/O")
    print("**************************************\n\n")
    with open(filename, "r+b") as f:
        file_size_standard_io = 0
        for line in f:
            output = line
            try:
                print(output.decode('utf-8').rstrip())
            except UnicodeDecodeError:
                print("hex: ", binascii.hexlify(output))
            file_size_standard_io += len(output)

    print("\n\n**************************************")
    print("File contents with memory mapped I/O")
    print("**************************************\n\n")
    with open(filename, "r+b") as f:
        map = mmap.mmap(f.fileno(), 0, access=mmap.PROT_READ)
        file_size_mmap = map.size()
        file_seek = 0
        while file_seek < file_size_mmap:
            output = map.readline()
            try:
                print(output.decode('utf-8').rstrip())
            except UnicodeDecodeError:
                print("hex: ", binascii.hexlify(output))
            file_seek += len(output)

    print("\n\n")
    print("Standard IO file size bytes: ", file_size_standard_io)
    print("MMAP IO file size bytes: ", file_size_mmap)
    if file_size_standard_io != file_size_mmap:
        print("\n********************************************************************************************")
        print("ALERT: File sizes do not match. File has cloaked data. Check contents above for hidden data.")
        print("********************************************************************************************\n\n")
    else:
        print("\nOK: File sizes are same so they are not cloaked.\n\n")

if __name__ == '__main__':
    main()

