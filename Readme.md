<img src="http://www.iconsdb.com/icons/preview/caribbean-blue/firewall-xxl.png" style="height:100px;width:100px;"> 

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
sudo python setup.py install
sudo bw -h (for help)
```

### Common Usage
```python
sudo python -c config/hostconfig.ini

sudo python -ih 192.168.0.3,192.168.1.0/24
sudo python -eh 192.168.1.1
```

