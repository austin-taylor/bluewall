<center><img src="http://www.iconsdb.com/icons/preview/caribbean-blue/firewall-xxl.png"> </center>

BLUEWALL
======

Bluewall is a firewall framework designed for offensive and defensive cyber professionals.
This framework allows Cybersecurity professionals to quickly setup their environment while 
staying within their scope.

Features
--------
#### Bluewall
*   Configure Firewall
*   Configure Hostname
*   Configure Interface(s)

#### Supported Operating Systems
*   Redhat/CentOS
*	**Windows configuration can be generated but not executed.


#### Commandline
*bw -c config/example.ini
**	See example configuration

#### Utils
*	Enumerate - Identify live hosts inside your network (coming soon)

#### Symantecs
* Target Host - Outbound connections
* Trusted Host - Incoming connections
* No Strike - Devices your computer should not communicate with

#### Getting Started
```python
# BUILT FOR PYTHON 2.x
sudo python setup.py install
sudo bw -h (for help)
```

### Help
```python
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
  -c CONFIG, --config CONFIG
                        Configuration for firewall
  --info                About Bluewall
```


### Common Usage
```python
# Setup Initial Environment using Configuration
sudo bw -c config/hostconfig.ini

# Export optional windows configuration
sudo bw -c config/hostconfig.ini -w autoconfig.ps1

# Add additional inbound host or ranges
sudo bw -ih 192.168.0.3,192.168.1.0/24

# Exclude host to communicate with
sudo bw -eh 192.168.1.1
```

