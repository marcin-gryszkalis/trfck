trfck
=====

Traffic check for FreeBSD.

```
Usage: trfck [-apbrmvhVD] [-n num] [-m num] [-s|-d] [-c -t num] [-f 'expr'] -i <if> [-i <if2> ... ]
  -i <if>   network interface (many interfaces can be specified)
  -h        show this info
  -n num    number of packets to capture (default 100, -1 for unlimited)
  -a        ascending sort (default descending)
  -m num    number of MACs to display in summary (all by default)
  -p        show percentage
  -b        count bytes (instead of packets)
  -r        count only remote ends (exclude own MACs)
  -l        mark local MACs with asterisk (see also -r)
  -s        show only source stats
  -d        show only destination stats
  -x        resolve MACs to IPs
  -X        resolve IPs to hostnames (implies -x)
  -c        continuous mode
  -o        turn off promiscuous mode
  -t num    time delay for continuous mode in seconds (default 10)
  -f 'expr' expr is a pcap-style BPF expression (man tcpdump)
  -v        be verbose (e.g. output each packet)
  -V        print version and exit
  -D        enable debug output (you are not supposed to understand it)
```

```
# trfck -i lan0 -p -b -r -x -c -t 1 -m 5  
Interfaces: lan0
Total packets: 2.90 KPkt (371  Pkts/s)
Total size: 1.45 MB (185.90 KB/s, 1.45 MBits/s)
SRC stats:
   76.50 KB  35.0 %10.1.2.68
   60.72 KB  27.8 %10.1.2.84
   38.60 KB  17.7 %10.1.2.10
    8.25 KB   3.8 %10.1.4.19
    6.63 KB   3.0 %10.1.2.78
DST stats:
  617.60 KB  48.5 %10.1.2.84
  440.87 KB  34.6 %10.1.2.10
   74.87 KB   5.9 %10.1.2.68
   56.76 KB   4.5 %10.1.4.19
   18.77 KB   1.5 %10.1.2.1
```

```
 # trfck -i dmz0  -l -c -t 1 -m 5 
Interfaces: dmz0
Total packets: 4.09 KPkt (524  Pkts/s)
Total size: 4.19 MB (536.86 KB/s, 4.19 MBits/s)
SRC stats:
    2.91 KPkt    d4:ae:52:b2:25:bf
    1.07 KPkt  * 00:07:e9:19:ec:68
     114  Pkt    00:15:17:26:86:3a
DST stats:
    3.02 KPkt  * 00:07:e9:19:ec:68
    1017  Pkt    d4:ae:52:b2:25:bf
      87  Pkt    00:15:17:26:86:3a
```
