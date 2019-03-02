import time
from bluewall.utils.shell import Interact
from bluewall.environment.rhel import config
from bluewall.base.validation import Validation
from bluewall.interact.set_firewall import SetFirewall
from bluewall.utils.shell import bcolors


class ConfigHost(object):
    """Class to configure the HOST from file input"""

    def __init__(self, config_in=None, DEBUG=False, VERBOSE=False, legacy=False):
        self.debug = DEBUG
        self.verbose = VERBOSE
        self.legacy = legacy
        self.win_config = []
        self.errlog = []
        self.it = Interact()

        if config_in is not None:

            self.configs = config(config=config_in, VERBOSE=self.verbose)
            Validation(config_in, verbose=self.verbose).validate()
            if self.verbose:
                self.set_firewall = SetFirewall(config_in=config_in, verbose=2)
            else:
                self.set_firewall = SetFirewall(config_in=config_in, verbose=0)
            self.target_ranges = self.configs.configs.get('target_range', '')
            self.trusted_range = self.configs.configs.get('trusted_range', '')
            self.nostrike = self.configs.configs.get('nostrike', '')

            if self.debug:
                print self.configs
        else:
            raise Exception("[-] Please specify a configuration path!")

        self.GREEN_PLUS = "[{gp}+{endc}]".format(gp=bcolors.OKGREEN, endc=bcolors.ENDC)

    def set_trusted(self):
        rules = []
        rules += self.set_firewall.allow_network_transport(direction='inbound', trusted=True, protocol='tcp',
                                                           networks=self.target_ranges)
        rules += self.set_firewall.allow_network_transport(direction='outbound', protocol='tcp', ports=[80],
                                                           networks=self.target_ranges)
        self.set_firewall.command_list.extend(rules)
        return


    def set_nostrike(self):
        if self.nostrike:
            rules = []
            for network in self.nostrike:
                rules += self.set_firewall.rule_builder('I', chain_options='i',
                                                        append_rule='1 -s {net} -j DROP'.format(net=network))
                rules += self.set_firewall.rule_builder('I', chain_options='o',
                                                        append_rule='1 -d {net} -j DROP'.format(net=network))
                self.set_firewall.command_list.extend(rules)
                if self.verbose:
                    print("{gp} {red}DISALLOWING{endr} traffic to {net} ".format(net=network, red=bcolors.FAIL,
                                                                                 endr=bcolors.ENDC, gp=self.GREEN_PLUS))
        return

    def autotrust(self):
        if self.target_ranges and self.trusted_range:
            outbound = self.target_ranges + self.trusted_range
            # Based on scan profile
            self.set_firewall.all_icmp_network(status=0, networks=outbound)
            self.set_firewall.allow_network_transport(direction='outbound', protocol='tcp', networks=outbound)
            self.set_firewall.allow_network_transport(direction='outbound', protocol='udp', networks=outbound)
            self.set_firewall.allow_network_transport(direction='inbound', trusted=True, protocol='udp', networks=self.trusted_range)
            self.set_firewall.allow_network_transport(direction='inbound', trusted=True, protocol='tcp', networks=self.trusted_range)
            self.set_firewall.allow_localhost()
        elif self.target_ranges and self.trusted_range == '':
            self.set_firewall.allow_network_transport(direction='outbound', protocol='tcp', networks=outbound)
            self.set_firewall.allow_network_transport(direction='outbound', protocol='udp', networks=outbound)
        elif self.trusted_range and self.target_ranges == '':
            self.set_firewall.allow_network_transport(direction='inbound', trusted=True, protocol='udp', networks=self.trusted_range)
            self.set_firewall.allow_network_transport(direction='inbound', trusted=True, protocol='tcp', networks=self.trusted_range)
        else:
            print("[{warn}INFO{end}] No target or trusted ranges detected in configuration".format(warn=bcolors.WARNING, endc=bcolors.ENDC))


    def redhat_setup(self, execute=False):
        print("[{info}PROCESSING RULES{ENDC}]\n".format(info=bcolors.OKBLUE, ENDC=bcolors.ENDC))
        self.set_firewall.flush_rules()
        self.set_firewall.set_defaults()
        self.autotrust()
        if self.nostrike:
            self.set_firewall.set_nostrike(self.nostrike)

        if execute:
            self.set_firewall.process_commands()

        if self.verbose:
            print("{gp} Configuration Applied.".format(gp=self.GREEN_PLUS))

        self.configs.config_rhel()
        return self.set_firewall.command_list

    def config_win(self, write_path='/cvah/autoconfig/autoconf.ps1'):
        self.write_path = write_path
        if self.write_path:
            self.filename = self.write_path.split('/')[-1]
        # set IP address

        # TODO: convert between netmask and CIDR prefix
        self.win_config.append('net start "DHCP Client"')
        self.win_config.append('netsh interface ipv4 set address em1 static ' +
                               self.configs.configs['win_ipaddr'][0] + ' ' +
                               self.configs.configs['netmask'][0] + ' ' +
                               self.configs.configs['gateway_addr'][0] + ' 1')
        self.win_config.append('net start dnscache')

        # set DNS
        self.win_config.append('netsh interface ipv4 set dns em1 static ' + self.configs.configs['dns'][0])

        # set hostname
        self.win_config.append('Rename-Computer -NewName ' + self.configs.configs['win_host'][0])

        # set Win firewall rules
        self.win_config.append('net start "windows firewall"')
        self.win_config.append('netsh advfirewall set allprofiles state on')
        self.win_config.append('netsh advfirewall firewall delete rule name=all')
        self.win_config.append('netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"')
        trusted_entries = '"' + ','.join(
            self.configs.configs['trusted_range'] + self.configs.configs['trusted_host']) + '"'
        self.win_config.append('netsh advfirewall firewall add rule name=trusted-in dir=in remoteip=' +
                               trusted_entries + ' action=allow')
        self.win_config.append('netsh advfirewall firewall add rule name=trusted-out dir=out remoteip=' +
                               trusted_entries + ' action=allow')
        target_entries = '"' + ','.join(
            self.configs.configs['target_range'] + self.configs.configs['target_host']) + '"'
        self.win_config.append('netsh advfirewall firewall add rule name=targets dir=out remoteip=' +
                               target_entries + ' action=allow')
        if self.nostrike:
            nostrike_entries = '"' + ','.join(
                self.configs.configs['nostrike_range'] + self.configs.configs['nostrike']) + '"'
            self.win_config.append('netsh advfirewall firewall add rule name=blacklist-in dir=in remoteip=' +
                                   nostrike_entries + ' action=block')
            self.win_config.append('netsh advfirewall firewall add rule name=blacklist-out dir=out remoteip=' +
                                   nostrike_entries + ' action=block')

        if self.verbose:
            self.win_config.append('netsh advfirewall show currentprofile')
            self.win_config.append('netsh advfirewall firewall show rule name=all')

        self.win_config.append('Write-Host "Verify config and press any key to continue"...')
        self.win_config.append('$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")')

        win_ps_file = None

        try:
            win_ps_file = open(self.write_path, 'w')
            if self.verbose:
                print("{gp} Windows configuration written to {file_path}".format(gp=self.GREEN_PLUS,
                                                                                 file_path=self.write_path))
        except Exception as e:
            self.log_error("Couldn't create Windows autoconfig script. %s" % e)

        if win_ps_file:
            [win_ps_file.write(str(pscmd) + '\n') for pscmd in self.win_config]
            win_ps_file.close()
            if self.verbose:
                for cmd in self.win_config:
                    print(str(cmd))

    def log_error(self, err):
        timestamp_err = "[" + time.ctime() + "]\t" + err
        self.errlog.append(timestamp_err)
        print timestamp_err
