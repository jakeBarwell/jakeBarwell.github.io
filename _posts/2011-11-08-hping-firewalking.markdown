---
layout: post
title:  "hping3 firewalking theory"
color: red
width:   6
height:  1
date:   2011-11-08 11:31:49 +0200
categories: network security
---
Here is a study I created in the second year of my degree. I look into the possibilities of using Hping3 as a firewalking tool.

Be warned this is a fair old read. :-)

### 1. Introduction

#### 1.1 Terminology

Throughout the study I will be using various terminology and acronyms. This section will layout the definitions to be used for the scope of this study.             

ACL – (Access Control List) is a set of rules that enforces a network policy. This study uses iptables when implementing a ACL.

Firewall – A Multi-homed host; configured to forward IP datagrams which uses a packet filtering ACL to control network traffic.

UDP – (User Datagram Protocol)

TCP – (Transmission Control Protocol)

ICMP – (Internet Control Message Protocol)


Tcpdump – A command line based packet analyser, allowing the user to intercept packets travelling too or from the machine it is running on.

Hop – One portion of the path between the source and its destination. Examples include Gateways and Routers.

TTL – The time to live field is used to limit the lifetime of a datagram across the internet and is decremented just before leaving the router. If the reduction causes the TTL to be 0 or less the router in question will send back a ICMP 11 error messsage (time to live exceeded). Letting you know at which host the packet expired.

#### 1.2 Hping3

Hping is a command line oriented TCP/IP packet assembler and analyser. Inspired by the Unix ping command it is not only able to send ICMP echo requests but also supports TCP, UDP, ICMP and RAW-IP protocol

Hping enables the user to perform a variety of tasks including:

 * Firewall Testing
 * Advanced port scanning
 * Advanced traceroute
 * Remote OS fingerprinting
 * Packet Crafting

In this study I will focus on explaining how to use hping to allow a user to test firewall policies using a technique called firewalking.

#### 1.3 Firewalking

TTL firewalking is method of testing a firewalls ACL and mapping port forwarded networks. The technique relies on analysing the ICMP TTL expired error message. The user sets the TTL to equal one when it reaches the firewall. If the packet is not filtered it will be forwarded but in the process of doing this, the TTL will reach 0 and a error message will be sent back to the user. Thus it is possible to map which ports are filtered based on the ICMP error messages received back.                                                                    

This study will provide an example of how this works. It will also look at the standard traceroute and port scanning functions available with hping which are vital in performing a successful firewalk. Finally it will look into the difficulties and solutions available when scanning UDP ports.

### 2. Setting up a Test Environment

It is possible to safely and accurately test hping using the Netkit virtual environment. hping comes pre-loaded on Netkit. To repeat the examples in this study, build a lab based on the network diagram in Figure A. On the web server virtual box start the bind DNS server and Apache running on ports 53 and 80 respectively.

1. Create three sub networks
    * 80.0.0.0/24
    * 146.182.172.0/24
    * 192.168.0.0/24
2. Create
    * User machine
        eth0 80.0.0.128
    * Gateway
        eth1 80.0.0.184
        eth0 146.182.172.254
    * Firewall
        eth0 146.182.172.185
        eth1 192.168.1.172
    * Webserver
        eth0 192.168.1.207
{% highlight bash %}
#!/bin/bash

##############################

#Flush all specific rules

iptables -F INPUT

iptables -F FORWARD

iptables -F OUTPUT

iptables -F -t  nat

################################

#Set Default Policies to drop everything

iptables -P INPUT DROP

iptables -P FORWARD DROP

iptables -P OUTPUT DROP

###############################

#Specific Rules for each example (PlaceHolder)

################################

 #Logging

 iptables -A FORWARD -j LOG --log-level 1

#################################
{% endhighlight %}

 Figure B: ACL script

In each example a ACL will be set up on the firewall. This is achieved using the iptables command.  The shell script is shown in Figure B, the section with specific example rules will be re-written at the beginning of each example. The rules used are taken from real world examples and simplified to show specific possibilities achievable with Hping.                     

### 3. A Traceroute Example

Add the following to the specific rules section of the iptables shell script and run it on the firewall machine:

iptables -A FORWARD -p ICMP -j ACCEPT

iptables -A INPUT -p ICMP -j ACCEPT

iptables -A OUTPUT -p ICMP -j ACCEPT

One interesting feature of hping3 is that it is possible to generate a more revealing Traceroute using any protocol. Using just the -T flag which enables the Traceroute function we can see how the packet is passed over each hop to its destination.
{% highlight bash %}
    user:~# hping3 -T 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): NO FLAGS are set, 40 headers + 0 data bytes
    hop=1 TTL 0 during transit from ip=80.0.0.184 name=UNKNOWN
    hop=1 hoprtt=13.3 ms
    hop=2 TTL 0 during transit from ip=146.182.172.185 name=UNKNOWN
    hop=2 hoprtt=12.1 ms
{% endhighlight %}
The command shown on line one initiates the traceroute – style IP expiry scan in the default TCP mode. The TTL count is incremented at each hop until the target host is reached. Lines three to six indicate that on hops one and two a ICMP time exceeded error message was received. The previous output shows the IP address of the hop and the host name if set, this information is useful when further analysing each hop.

No further response is received after the second hop. The traceroute can be peformed again in ICMP mode to try and reach the host.
{% highlight bash %}
    user:~# hping3 -T -1 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): icmp mode set, 28 headers + 0 data bytes
    hop=1 TTL 0 during transit from ip=80.0.0.184 name=UNKNOWN
    hop=1 hoprtt=2.7 ms
    hop=2 TTL 0 during transit from ip=146.182.172.185 name=UNKNOWN
    hop=2 hoprtt=1.8 ms
    len=28 ip=192.168.1.207 ttl=62 id=864 icmp_seq=2 rtt=5.0 ms
    len=28 ip=192.168.1.207 ttl=62 id=865 icmp_seq=3 rtt=2.3 ms
{% endhighlight %}
The command on line one uses the -1 flag which sets hping to run in ICMP mode. The default setting for this mode is to send an Echo request and listen for a reply. Lines seven and eight show the echo replies being received from the third hop. This command can be run to send various types of ICMP requests, please refer to the hping Cheatsheet link for more information.              


The findings from the two prior commands indicate that the second hop is acting as a firewall to at least some degree. It is dropping TCP SYN packets but allowing ICMP echo requests. We have also discovered the number of hops between the user machine and the target web server. This information is vital in analysing particular machines.                 

### 4. A Port Scan Example

The iptables shell script should be run on the firewall and the specific rules section should contain the following:

iptables -A FORWARD -p UDP --dport 53 -j ACCEPT

iptables -A FORWARD -p TCP --dport 53 -j ACCEPT

iptables -A FORWARD -p TCP --dport 80 -j ACCEPT

iptables -A FORWARD -p TCP --dport 443 -j ACCEPT

iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED

In this example we are going to send some custom packets to generally used ports to test their behaviour.
{% highlight bash %}
    user:~# hping3 --scan 80,443,53,25 -S 192.168.1.207 -V
    using eth0, addr: 80.0.0.128, MTU: 1500
    Scanning 192.168.1.207 (192.168.1.207), port 80,443,53,25
    4 ports to scan, use -V to see all the replies
    +----+-----------+---------+---+-----+-----+-----+
    |port| serv name |  flags  |ttl| id  | win | len |
    +----+-----------+---------+---+-----+-----+-----+
      53 domain     : .S..A...  62     0  5840    44
      80 www        : .S..A...  62     0  5840    44
     443 https      : ..R.A...  62     0     0    40
    All replies received. Done.
    Not responding ports: (25 smtp)
{% endhighlight %}

The command on line one uses the following options

* – scan – Produces a report of all the responses received from the specified ports.
* -S – Sends a TCP SYN packet.
* -V – Shows all replies received.

The table from lines five to eleven shows the responses that were received back and line twelve shows the ports that did not respond.

* Ports 80 and 53 – Responded with a SYN ACK.
* Port 443 – Responded with a RST.
* Port 25 – No response was received.

These responses or lack of, give an idea of the ACL in place on the firewall and the services available on the target box.

* A SYN ACK response indicates that port is open and that service is running.
* A RST response indicates the port is closed.
* No response indicates that the packet is being dropped by the firewall.

The report output also shows the service name that is run on that port, which can be used for further more in depth testing by specifically creating packets with the data expected by that service.

The information this type of scan provides could be used by an admin to fix problems such as allowing TCP and UDP requests to port 53 as on the previous example, or by a hacker tying to find a vulnerable service.

### 5. Firewalking Example

The iptables shell script should be run on the firewall and the specific rules section should contain the following:

iptables -t nat -A PREROUTING -p tcp -d 146.182.172.185 --dport 25 -j DNAT --to-destination 192.168.1.207:25

iptables -t nat -A PREROUTING -p tcp -d 146.182.172.185 --dport 53 -j DNAT --to-destination 192.168.1.207:53

iptables -t nat -A PREROUTING -p tcp -d 146.182.172.185 --dport 80 -j DNAT --to-destination 192.168.1.207:80

iptables -A FORWARD -p tcp -j ACCEPT

iptables -A OUTPUT -p icmp -j ACCEPT

In this example the internal network is performing port forwarding on the packets. This has the effect of the edge firewall hiding the true web server, showing a different network perspective from the outside.

Prior to performing this firewalk the previous two examples would be deployed on the public facing IP address. This reconnaissance would show that it appears that this node is two hops away and is acting as a firewall, DNS server and a web server. The following commands will determine if this is the case.
{% highlight bash %}
    user:~# hping3 --scan 20-83 -S -t 2 146.182.172.185 -V
    Scanning 146.182.172.185 (146.182.172.185), port 20-83
    64 ports to scan, use -V to see all the replies
    +----+-----------+---------+---+-----+-----+-----+
    |port| serv name |  flags  |ttl| id  | win | len |
    +----+-----------+---------+---+-----+-----+-----+
      25:                       63    68 62989   (ICMP  11   0 from 146.182.172.185)
      53:                       63    68 62990   (ICMP  11   0 from 146.182.172.185)
      80:                       63    68 62991   (ICMP  11   0 from 146.182.172.185)
    All replies received. Done
{% endhighlight %}
The command on line one uses the following options

* – scan – Produces a report of all the responses received from the specified ports.
* -S – Sends a TCP SYN packet.
* -V – Shows all replies received.
* -t – Sets the TTL flag to that specified.

This has effectively reverse engineered the ACL rules on this firewall. The output from lines five to ten, show three ICMP type 11 error messages (Time To Live Exceeded) being received for ports 25, 53 and 80. This means:

* The firewall has accepted these packets and attempted to forward them to the destination but the TTL reached 0 before reaching it.
* The other packets were dropped as the firewall did not attempt to forward them and no ICMP error message was received.

We have clarified that hop two is acting as a firewall and that there is at least one more hop to reach the box running the services. Thus we increase the TTL count by one which will allow us to see if the next hop is running the services, if not then we increase
it again
{% highlight bash %}
    user:~# hping3 --scan 20-83 -S -t 3 146.182.172.185 -V
    using eth0, addr: 80.0.0.128, MTU: 1500
    Scanning 146.182.172.185 (146.182.172.185), port 20-83
    64 ports to scan, use -V to see all the replies
    +----+-----------+---------+---+-----+-----+-----+
    |port| serv name |  flags  |ttl| id  | win | len |
    +----+-----------+---------+---+-----+-----+-----+
      25 smtp       : ..R.A...  62     0     0    40
      53 domain     : .S..A...  62     0  5840    40
      80 www        : .S..A...  62     0  5840    44
    All replies received. Done.
{% endhighlight %}
Lines nine and ten show that a SYN ACK was received showing that the server is reachable and the service is listening. These findings prove the server is three hops away and the firewall is performing port forwarding.

The example above illustrates the fundamental commands, steps and basic
trace output when firewalking. This kind of trace tells the user which host is answering the request to a specific port and which hops it is jumping to reach them. This technique can be applied for both TCP and UDP.

### 6. UDP Ports

The iptables shell script should be run on the firewall machine and the specific rules section should contain the following:

iptables -A FORWARD -p UDP -j ACCEPT

iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED

Scanning UDP ports can be relatively tough. If being used in firewalking type trace it can lead to ambiguous results.

A Common technique that is used; is to send packets with no payload to UDP ports and if nothing is received back it is assumed that the port is open. This technique works because on a closed port you get a port unreachable ICMP message from the target OS. Open ports do not respond to zero payload packets.
{% highlight bash %}
    user:~# hping3 -2 -p 11 -c 1 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): udp mode set, 28 headers + 0 data bytes
    ICMP Port Unreachable from ip=192.168.1.207 name=UNKNOWN
    user:~# hping3 -2 -p 52 -c 1 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): udp mode set, 28 headers + 0 data bytes
    ICMP Port Unreachable from ip=192.168.1.207 name=UNKNOWN
{% endhighlight %}
The options used in the command on lines one and four are:

* -2 – This runs Hping in UDP mode
* -p – Sets the destination port to that specified.
* -c – This sets the amount of packets to send out.

Lines three and six show that the two closed ports return a ICMP port unreachable error message. The following output shows no response being received when sending the packet to an open port.
{% highlight bash %}
    user:~# hping3 -2 -p 53 -c 1 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): udp mode set, 28 headers + 0 data bytes
    --- 192.168.1.207 hping statistic ---
    1 packets transmitted, 0 packets received, 100% packet loss
{% endhighlight %}
These findings have enabled the discovery of an open UDP port on the target box. However in live networks firewalls usually block such outgoing packets like ICMP to prevent this type of discovery.

The shell script should be run on the firewall and the specific rules section should contain the following:

iptables -A FORWARD -p UDP --dport 53 -j ACCEPT

iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED

The ACL has been updated to drop any packets not destined for port 53. So the previous technique will not work, as no response will be received from both closed and open ports. To bypass the ACL I have created a .txt file containing roughly 120 bytes of random data. This file is going to form the payload for each packet. At the same time as running the following command I started a tcpdump to capture what response would be received.
{% highlight bash %}
    user:~# hping3 -2 -p ++50 -d 120 -E file.txt 192.168.1.207
    HPING 192.168.1.207 (eth0 192.168.1.207): udp mode set, 28 headers + 120 data bytes
    [main] memlockall(): Success
    Warning: can't disable memory paging!
    len=40 ip=192.168.1.207 ttl=62 DF id=0 seq=3 rtt=4.1 ms
{% endhighlight %}
The options in the command on line 1 are as follows:

* -2 – This runs Hping in UDP mode
* -p – Sets the destination port to that specified.
* ++50 – Increases the port number by 1 from port 50 for each packet sent.
* -d – The data size of the file being used as the payload for the packet.
* -E – Insert the file specified into the packets data.

The following output shows the tcpdump capture from the previous command.
{% highlight bash %}
    user:~# tcpdump
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
    16:11:06.846576 IP 80.0.0.128.1498 &gt; 192.168.1.207.re-mail-ck: UDP, length 120
    16:11:07.871950 IP 80.0.0.128.1499 &gt; 192.168.1.207.51: UDP, length 120
    16:11:08.882069 IP 80.0.0.128.1500 &gt; 192.168.1.207.52: UDP, length 120
    16:11:09.892153 IP 80.0.0.128.1501 &gt; 192.168.1.207.domain: 25196 updateM+ [b2&amp;3=0x6168] [25186a] [25186q] [25186n] [25186au][|domain]
    16:11:09.895497 IP 192.168.1.207.domain &gt; 80.0.0.128.1501: 25196 updateM FormErr- [0q] 0/0/0 (12)
    16:11:09.895607 IP 80.0.0.128 &gt; 192.168.1.207: ICMP 80.0.0.128 udp port 1501 unreachable, length 48
    16:11:10.902042 IP 80.0.0.128.1502 &gt; 192.168.1.207.54: UDP, length 120
    16:11:11.912207 IP 80.0.0.128.1503 &gt; 192.168.1.207.55: UDP, length 120
{% endhighlight %}

* Lines four to six show a packet going from the user to the target with the taget port being incremented each time. No response is received back.
* Lines seven and eight however show the packet being sent to port 53 on the target machine and a DNS format error message being received.
* This error response shows that port 53 is open.

This example shows the flexibility that is achievable with hping when facing different scenarios. The user can generate crafted packets to bypass the ACL rules in place on the firewall.

### 7. Conclusion

Hping3 should be included in any serious penetration testers or network analysts tool set. It allows the user to craft and send custom packets and perform remote scanning using various protocols.

In the study hping was used to test what traffic the firewall was allowing into the network. The firewalking technique allowed users to map ACL rules and port forwarded networks.

This study is intended to give a brief outline of hping3 and explore the possibilities when using hping to test security policies or 'firewalk'. To fully understand the possibilities and capabilities of the hping and it's Tcl scripting features I would recommend further research.

### 8. References / Links

Hping Cheatsheet [WWW] Available at: http://sbdtools.googlecode.com/files/hping3_cheatsheet_v1.0-ENG.pdf [Accessed 21/02/11]

Hping wiki [WWW] Available at: http://www.thesprawl.org/memdump/?entry=5#External%20Links [Accessed 21/02/11]

An Introduction to the Tcl programming language [WWW] Available at: http://www.invece.org/tclwise/introduction.html [Accessed 21/02/11]

Host fingerprinting and firewalking with hping [WWW] Available at: http://www.ouah.org/HostFingerprinting.pdf [Accessed 21/02/11]

Security Testing with Hping: At the hop [WWW] Available at: www.linux-magazine.com/w3/issue/99/038-041_hping.pdf [Accessed 21/02/11]
