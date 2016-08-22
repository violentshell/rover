# rover
Proof of Concept code for CVE-2016-5696

Rover is a small python program to discover abitrary client source ports as shown in CVE-2016-569. Once the source port is known, the 4 tuple of information needed to confirm that two host are communicating can be completed. When run, rover establishes a connection with the target server, syncs its internal clock to the server challenge ack time, then begins to search through the default ephemeral port range of most linux hosts (this can be changed if required).

For more information, find the original paper [here](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_cao.pdf)

This has been tested to run on kali 1.0  against an **Ubuntu 14.04 SSH server**. It should work against others, however some modification to the code may/will be needed. Requirements are:

1. Python2.7
2. Scapy 2.3.2

Usage is as follows:
```
rover.py [-h] -c 192.168.1.1 -s 192.168.1.10 -p 22 [-v v, vv]

CVE2016-5969 Demonstrator.

optional arguments:
  -h, --help       show this help message and exit
  -c 192.168.1.1   The target client IP.
  -s 192.168.1.10  The target server IP.
  -p 22            The target server port.
  -v v, vv         The verbosity level
```

Rover will complete in approx 1-2 minutes, depending on the quality of sync.

![alt text](https://cloud.githubusercontent.com/assets/21149221/17834620/a556cc6e-6788-11e6-9f9b-04f98756a71b.png)

## Some important notes. 
1. Rover is bandwith dependant. It currently sends out 700 packets a second. If it fails to do so in the required time, the program will fail.
2. I have included the line: `os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')` because the kernel will reset a scapy connection by default. This must be in IPTABLES for the program to work.
3. If you use vmware, keep in mind that workstation and player limit bandwith. This may cause issues. If so, use a physical host for the attack machine.
