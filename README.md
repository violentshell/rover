# rover
Proof of Concept code for CVE-2016-5696

Rover finds abritrary client ports to complete the 4 tuple of information needed to confirm that two host are communicating. When run, rover establishes a connection with the server, syncs its internal clock to the server challenge ack time, then begins to search through the default ephemeral port range of most linux hosts (this can be changed if required).

This has been tested to run on kali 1.0  against an Ubuntu 14.04 server. It should work against others, however some modification may be needed. Requirements are:

Python2.7
Scapy 2.3.2

Usage is as follows:
usage: rover.py [-h] -c 192.168.1.1 -s 192.168.1.10 -p 22 [-v v, vv]

CVE2016-5969 Demonstrator.

optional arguments:
  -h, --help       show this help message and exit
  -c 192.168.1.1   The target client IP.
  -s 192.168.1.10  The target server IP.
  -p 22            The target server port.
  -v v, vv         The verbosity level

