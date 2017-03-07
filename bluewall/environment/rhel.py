from bluewall.utils.shell import Interact
from bluewall.utils.superset import AOR
from bluewall.utils.shell import bcolors
import random


class config(object):
    def __init__(self, VERBOSE=False, DEBUG=False, config=None, legacy=False):
        self.verbose = VERBOSE
        self.debug = DEBUG
        self.it = Interact()
        self.ethIFName = None
        self.mac_address = None
        self.legacy = legacy
        self.GET_HOSTNAME = "nmcli d | grep ethernet | cut -d' ' -f 1"
        self.ETH_CONFIG_PATH = "/etc/sysconfig/network-scripts/ifcfg-"
        self.SET_HOSTNAME = "hostnamectl set-hostname "

        if config is not None:
            self.configs = AOR(config=config).configs
            if self.debug:
                print self.configs
        else:
            print("[*] No config was passed. Some functions may not work properly")

    def get_rhel_eth_ifaces(self):
        return [iface for iface in Interact().run_command("nmcli d | cut -d' ' -f 1").split('\n')[1:] if iface != '']

    def get_rhel_eth_name(self):
        eth_if_name = self.value_extract('iface')
        #eth_if_name = Interact().run_command(self.GET_HOSTNAME).strip()
        return eth_if_name

    def generate_mac(self):
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x".upper() % x, mac))

    def config_rhel(self):
        self.ethIFName = self.get_rhel_eth_name()

        if self.ethIFName:
            self.create_rhel_eth_config()
            self.cycle_rhel_ethernet(restart_network=False)
        else:
            self.log_error("Error, ethernet device not found.  RHEL interface not configured.")
        self.set_rhel_hostname()
        return

    def value_extract(self, key):
        setting = ''
        try:
            setting = self.configs.get(key)[0]
        except:
            pass
        return setting

    def create_rhel_eth_config(self):
        config_path = self.ETH_CONFIG_PATH + self.ethIFName
        if self.verbose or self.debug:
            print "writing eth config to " + config_path

        dns_addr = self.value_extract('dns')
        rh_ipaddr = self.value_extract('rh_ipaddr')
        cidr_prefix = self.value_extract('cidr_prefix')
        gateway_addr = self.value_extract('gateway_addr')
        try:
            self.mac_address = self.value_extract('rh_mac')
        except:
            self.mac_address = None

        if self.debug:
            print self.configs.get('dns')[0]
            print self.configs.get('rh_ipaddr')[0]
            print self.configs.get('cidr_prefix')[0]
            print self.configs.get('gateway_addr')[0]

        with open(config_path, 'w') as c:
            c.write('TYPE="Ethernet"' + '\n')
            c.write('BOOTPROTO=none' + '\n')
            c.write('NAME=' + self.ethIFName + '\n')
            c.write('DEVICE="' + self.ethIFName + '"\n')
            c.write('ONBOOT=no\n')
            c.write('DEFROUTE="yes"\n')
            c.write('IPV4_FAILURE_FATAL=no\n')
            c.write('DNS1=' + dns_addr + '\n')
            c.write('IPADDR=' + rh_ipaddr + '\n')
            c.write('PREFIX=' + cidr_prefix + '\n')
            c.write('GATEWAY=' + gateway_addr + '\n')

            if self.mac_address is not None or self.mac_address != '':
                if self.mac_address == '*':
                    c.write("MACADDR=" + self.generate_mac() + '\n')
                else:
                    c.write("MACADDR=" + self.mac_address + '\n')

        if self.verbose:
            verify_config = open(config_path).read()
            print("[{blue}CONFIGURATION{end}]".format(blue=bcolors.OKBLUE, end=bcolors.ENDC))
            print(verify_config)

    def cycle_rhel_ethernet(self, restart_network=False):
        self.it.run_command("ifdown " + self.ethIFName)
        if self.verbose:
            print("[+] Interface {name} shutdown.".format(name=self.ethIFName))
        if restart_network:
            self.restart_network_service()
        self.it.run_command("ifup " + self.ethIFName)
        if self.verbose:
            print("[+] Interface {name} brought up.".format(name=self.ethIFName))

    def restart_network_service(self):
        self.it.run_command("systemctl restart network")
        if self.verbose:
            print("[+] Restarting Network Service")

    def set_rhel_hostname(self):
        try:
            rh_host = self.configs['rh_host'][0]
        except:
            rh_host = self.it.demand_input("RHEL hostname not defined.  Please enter a hostname: ")

        self.it.run_command(self.SET_HOSTNAME + rh_host)

    def legacy_files(self, trusted_file=None, target_file=None, nostrikes_file=None):
        if self.legacy:
            """ process targets """
            if target_file:
                AOR.target_parser(target_file)
                if self.verbose:
                    print("[+] Target file written to {target_file}".format(target_file=target_file))

            if trusted_file:
                AOR.trusted_parser(trusted_file)
                if self.verbose:
                    print("[+] Trusted file written to {trusted_file}".format(trusted_file=trusted_file))

            if nostrikes_file:
                AOR.trusted_parser(nostrikes_file)
                if self.verbose:
                    print("[+] No-strikes file written to {nostrikes_file}".format(nostrikes_file=nostrikes_file))
                    # TODO: Call firewall script
