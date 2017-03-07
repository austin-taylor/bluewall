<p align="center"><img src="http://www.austintaylor.io/images/bluewall.png"></p>

BLUEWALL
======

Bluewall is a firewall framework designed for offensive and defensive cyber professionals.
This framework allows Cybersecurity professionals to quickly setup their environment while 
staying within their scope.

Credit
-------
Inspired by Andrew Benson's <a href="https://github.com/abenson/hostfw">hostfw iptable generation script</a>.


Features
--------
#### Bluewall
    * Configure Firewall
    * Configure Hostname
    * Configure Interface(s)

#### Supported Operating Systems
    * Redhat/CentOS
    * Windows configuration can be generated but not executed.


#### Commandline
    *  bw -c config/example.ini
    ** See example configuration

#### Utils
    * Enumerate - Identify live hosts inside your network (coming soon)

#### Symantecs

    * Target Host - Outbound communication
    * Trusted Host - Bidirectional communication
    * No Strike - Devices your computer should not communicate with

#### Setup

```bash
# BUILT FOR PYTHON 2.x
sudo python setup.py install
sudo bw -h (for help)
```

## Getting Started

```bash
# Setup Initial Environment using Configuration
sudo bw -c config/hostconfig.ini

# Export optional windows configuration
sudo bw -c config/hostconfig.ini -w autoconfig.ps1

# Add additional inbound host or ranges
sudo bw -ih 192.168.0.3,192.168.1.0/24

# Exclude host to communicate with
sudo bw -eh 192.168.1.1

# Super easy wizard mode
sudo bw --wizard
```

### Help
```
usage: bw [-h] [-V] [-v] [-r] [-p] [-i] [-d] [-w WINDOWS_CONFIG]
          [-ot TCP_PORTS_OUT] [-ou UDP_PORTS_OUT] [-it TCP_PORTS_IN]
          [-iu UDP_PORTS_IN] [-oh OUTBOUND_HOSTS] [-ih INBOUND_HOSTS]
          [-eh EXCLUDE_HOSTS] [-l] [-s] [-q] [-D] [-A] [-F] [-S] [-c CONFIG]
          [--info]

         /////////////////////////////////////////////////////
        |  _____ __    _____ _____ _ _ _ _____ __    __      |
        | |  __ |  |  |  |  |   __| | | |  -  |  |  |  |     |
        | |  __-|  |__|  |  |   __| | | |     |  |__|  |__   |
        | |_____|_____|_____|_____|_____|__|__|_____|_____|  |
        |                                                    |
         \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
            A python framework to automate firewall setup.

        Defaults:
            Outbound connections will be allowed on all ports to all hosts.
            Inbound connections will be limited to related outbound traffic.
            DHCP will be enabled.
            Ping responses will be enabled.
            Unsolicited inbound connections will be dropped.

        

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Display Version
  -v, --verbose         Verbose Mode
  -r, --reset           Send TCP RST instead of dropping packet.
  -p, --disallow_ping   Disallow incoming PING
  -i, --allow_outbound_icmp
                        Don't restrict ICMP types
  -d, --disallow_dhcp   Disallow DHCP
  -w WINDOWS_CONFIG, --windows_config WINDOWS_CONFIG
                        Generate Windows Configuration. Usage: bw -w
                        config.ps1
  -ot TCP_PORTS_OUT, --tcp_ports_out TCP_PORTS_OUT
                        Comma separated list of allowed TCP ports outbound
  -ou UDP_PORTS_OUT, --udp_ports_out UDP_PORTS_OUT
                        Comma separated list of allowed UDP ports outbound
  -it TCP_PORTS_IN, --tcp_ports_in TCP_PORTS_IN
                        Comma separated list of allowed TCP ports inbound
  -iu UDP_PORTS_IN, --udp_ports_in UDP_PORTS_IN
                        Comma separated list of allowed UDP ports inbound
  -oh OUTBOUND_HOSTS, --outbound_hosts OUTBOUND_HOSTS
                        Restrict outbound to specified hosts. -oh
                        192.168.3.0/24,192.168.4.0/24
  -ih INBOUND_HOSTS, --inbound_hosts INBOUND_HOSTS
                        Restrict outbound to specified hosts. -ih
                        192.168.3.0/24,192.168.4.0/24
  -eh EXCLUDE_HOSTS, --exclude_hosts EXCLUDE_HOSTS
                        Exclude hosts -eh 192.168.3.0/24
  -l, --log_exceptions  Log Exceptions
  -s, --simulate        Simulate only.
  -q, --quiet           Quiet (don't display status messages
  -D, --deny_all        Absolute Deny all
  -A, --allow_all       Absolute allow all
  -F, --flush           Flush IPTables
  -S, --show_rules      Show rules after setting
  --wizard              Addressing and firewall wizard mode
  -c CONFIG, --config CONFIG
                        Configuration for firewall
  --info                About Bluewall
```

### Config Example

example.ini
```
[local_config]
iface=em1
rh_host=RHEL-Example
rh_ipaddr=192.168.1.42
netmask=255.255.255.0
gateway_addr=172.16.63.1
dns=8.8.8.8
#win_ipaddr=192.168.1.42 - Optional windows IP Address
#
# Optional Windows host (Bluewall will generate a config file for windows)
win_host=WINExample
# MAC Addresses must be ALL CAPS Valid: AA:93:AB:EF:00:01
# rh_mac=* will generate random MAC address
rh_mac=*

[firewall_config]
# Target Range are networks you want to allow outbound communication with.
target_range=172.16.63.0/24
target_range=192.168.2.0/24
#
# Nostrike addresses are devices your computer should NOT communicate with
nostrike=192.168.2.1
#
# Trusted Range are networks you wish to have bi-directional communication with
trusted_range=172.16.63.0/24
trusted_host=42.42.42.42
```

### Output
```bash
[ataylor@localhost bluewall]$ sudo bw -c configs/exampleconfig.ini 
[OK] 192.168.1.101 is a valid setting for dns
[OK] 192.168.1.1 is a valid setting for gateway_addr
[OK] 24 is a valid setting for cidr_prefix
[OK] 192.168.1.254 is a valid setting for nostrike
[OK] * is a valid setting for rh_mac
[OK] WINtaylor is a valid setting for win_host
[OK] 192.168.2.0/24 is a valid setting for target_range
[OK] 192.168.3.0/24 is a valid setting for target_range
[OK] 192.168.1.30 is a valid setting for rh_ipaddr
[OK] RHEL-taylor is a valid setting for rh_host
[OK] 42.42.42.42 is a valid setting for trusted_host
[OK] 192.168.1.0/24 is a valid setting for trusted_range
[OK] 192.168.1.50 is a valid setting for win_ipaddr
==============================

[VALID CONFIG] No Errors Detected.

CONFIGURING
writing eth config to /etc/sysconfig/network-scripts/ifcfg-ens33
[CONFIGURATION]
TYPE="Ethernet"
BOOTPROTO=none
NAME=ens33
DEVICE="ens33"
ONBOOT=no
DEFROUTE="yes"
IPV4_FAILURE_FATAL=no
DNS1=192.168.1.101
IPADDR=192.168.1.30
PREFIX=24
GATEWAY=192.168.1.1
MACADDR=00:16:3E:52:7F:8D

[+] Interface ens33 shutdown.
[+] Restarting Network Service
[+] Interface ens33 brought up.
[+] Rules Flushed!
[+] Allowing outbound ICMP/traceroute to 192.168.2.0/24...
[+] Allowing outbound ICMP/traceroute to 192.168.3.0/24...
[+] Allowing outbound ICMP/traceroute to 192.168.1.0/24...
[+] Limiting outbound TCP connections to 192.168.2.0/24.
[+] Limiting outbound TCP connections to 192.168.3.0/24.
[+] Limiting outbound TCP connections to 192.168.1.0/24.
[+] Limiting outbound UDP connections to 192.168.2.0/24.
[+] Limiting outbound UDP connections to 192.168.3.0/24.
[+] Limiting outbound UDP connections to 192.168.1.0/24.
[+] Limiting inbound UDP connections to 192.168.1.0/24.
[+] Limiting inbound TCP connections to 192.168.1.0/24.
[+] Allowing traffic for localhost.
[+] 192.168.1.254 applied to NOSTRIKE
$ iptables -nvL
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DROP       all  --  *      *       192.168.1.254        0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       127.0.0.0/8          127.0.0.0/8         
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.1.0/24      
    0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.1.0/24      

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DROP       all  --  *      *       0.0.0.0/0            192.168.1.254       
    0     0 ACCEPT     all  --  *      *       127.0.0.0/8          127.0.0.0/8         
    0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.1.0/24      
    0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.3.0/24      
    0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.2.0/24      
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.1.0/24      
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.3.0/24      
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.2.0/24      
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.1.0/24       icmptype 0
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.1.0/24       icmptype 8
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.3.0/24       icmptype 0
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.3.0/24       icmptype 8
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.2.0/24       icmptype 0
    0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            192.168.2.0/24       icmptype 8

[+] Setup Complete.
```


