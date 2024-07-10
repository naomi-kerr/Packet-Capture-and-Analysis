# Packet Capture + Analysis

## Objective

Capture a packet using tcpdump and the command line. Use Wireshark to open up the .pcap file and analyze it. 

### Skills Learned

* tcpdump cli packet capture
* Wireshark filters
* Wireshark GUI & information structure

### Tools Used

 * Linux CLI
 * tcpdump
 * Wireshark

## Steps

1. Use the Linux CLI to initiate a packet capture via tcpdump and save
2. Open the captured packets with Wireshark
3. Filter through the captured packets for a specific IP address
4. Use additional filters to find different types of packets for different purpos

## Process

### tcpdump capture

Start by identifying the NIC's that are available on your system by using `sudo ifconfig`, `ip address show`, or `tcpdump -D`

```
naomi@local-machine:~$ sudo tcpdump -D
1.eth0 [Up, Running]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
4.nflog (Linux netfilter log (NFLOG) interface)
5.nfqueue (Linux netfilter queue (NFQUEUE) interface)
```

Next, use `sudo tcpdump [options]` to capture the packet.
```
naomi@local-machine:~$ sudo tcpdump -i eth0 -nn -c9 port 80 -w capture.pcap &
```
In the example above, `-i eth0` indicates we want to capture packets sent to the eth0 network device, `-nn` tells tcpdump not to translate IP addresses or port numbers, `-c9` limits the capture to 9 packets, `port 80` only captures packets sent through port 80, `-w` writes the .pcap file with the provided filename, and `&` runs the process in the background. Once finished the terminal will output something like this: 
```
naomi@local-machine:~$ 9 packets captured
10 packets received by filter
0 packets dropped by kernel
```

Lastly, check that the packet has been saved to the appropriate place 
### Wireshark Analysis
Start with double clicking the .pcap file to open it with Wireshark as it is the default program for .pcap. 

In this example, the IP Address `142.250.1.139` is the target. We start by using `ip.addr == 142.250.1.139` to filter for any traffic that involves this IP.

Opening up the first tcp packet, we can view the packet details:
![screenshot](Packet-Analysis-01.png) 
#### Frame
The frame shows up the timestamps, datestamps, the protocol used, and the port that was used. 
![screenshot](Packet-Analysis-02.png)
#### Ethernet II
The Ethernet II section shows us the MAC addresses are associated with the packet and which Internet Protocol version is being used (IPv4 or IPv6).   
![screenshot](Packet-Analysis-03.png)

#### IPv4 
The Internet Protocol version 4 section shows us more details about the packet as well as details we've gotten from other sections, such as Internet protocol version, header length, total length, TTL (time to live), protocol (tcp, udp, etc.) and the source and destination addresses. 
![screenshot](Packet-Analysis-04.png)

#### Transmission Control Protocol
The last section to review is the Transmission Control Protocol (TCP) section. In this section we are primarily concerned with the packet header information that we haven't seen in other sections. This includes the source port, sequence number, the flags, checksum, and urgent pointer. 
![screenshot](Packet-Analysis-05.png)

#### Analysis
In the packet used above, we see basic http traffic being sent via TCP through port 80 from `172.21.224.2` (a local network address) to `142.250.1.139` (a Google IP address).  

### Additional Filters

#### IP Source & Destination
Using the filter `ip.src == 142.250.1.139` the packets are filtered to only traffic that is sent by the IP `142.250.1.139`. We can do the same thing for traffic that is direct to `142.250.1.139` with the filter `ip.dst == 142.250.1.139`. 
![screenshot](Packet-Analysis-06.png)
![screenshot](Packet-Analysis-07.png)
#### MAC Address
The filter `eth.addr == 42:01:ac:15:e0:01` is used to filter all traffic that is associated with the MAC address `42:01:ac:15:e0:01`. 
![screenshot](Packet-Analysis-08.png)
#### Ports
Filtering for ports involves using both the protocol and the port that we are interested in filtering for. In this case, we filter for both TCP and UDP traffic over port 80 using `tcp.port == 80 || udp.port == 80`. By using the double pipe "or" operator, the system will return any packets that match TCP traffic over port 80 and any packet that match UDP traffic over port 80. 
![screenshot](Packet-Analysis-09.png)
#### String Searches
Lastly, we can use string searches by using the contains filter. This will return packets that have the specified string within them. In this case, we use `TCP contains "curl"` to find any traffic that was initiated using the `curl` command. 
![screenshot](Packet-Analysis-10.png)