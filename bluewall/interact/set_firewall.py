from bluewall.base.config import BWConfig
from bluewall.base.cli_parser import CLIParser
from bluewall.utils.shell import Interact
from bluewall.utils.shell import bcolors
import ipaddr


class SetFirewall(CLIParser):
    def __init__(self, config_in=None, verbose=0, log_response=False, execute=True):
        super(SetFirewall, self).__init__(verbose=verbose)

        self.config_in = config_in
        self.verbose = verbose
        self.parse_args()
        self.it = Interact()
        self.root_check = self.it.root_check(debug=False)
        self.firewall = {}
        self.execute = execute
        self.command_list = []
        # TODO Check if IPTABLES is in path and raise Exception if not

        if self.config_in is not None:
            self.config = BWConfig(self.config_in)

            # Read in config values
            self.firewall['logexcept'] = self.config.get('firewall', 'LOGEXCEPT')
            self.firewall['resetconn'] = self.config.get('firewall', 'RESETCONN')
            self.firewall['allowping'] = self.config.get('firewall', 'ALLOWPING')
            self.firewall['allowdhcp'] = self.config.get('firewall', 'ALLOWDHCP')
            self.firewall['ob_tcp'] = self.config.get('firewall', 'OB_TCP')
            self.firewall['ob_udp'] = self.config.get('firewall', 'OB_UDP')
            self.firewall['ib_tcp'] = self.config.get('firewall', 'IB_TCP')
            self.firewall['ib_udp'] = self.config.get('firewall', 'IB_UDP')
            self.firewall['ob_targs'] = self.config.get('firewall', 'OB_TARGS')
            self.firewall['ib_targs'] = self.config.get('firewall', 'IB_TARGS')
            self.firewall['ex_targs'] = self.config.get('firewall', 'EX_TARGS')
            self.firewall['autotrust'] = self.config.get('firewall', 'AUTOTRUST')
            self.firewall['allow_all'] = self.config.get('firewall', 'ALLOWALL')
            self.firewall['deny_all'] = self.config.get('firewall', 'DENYALL')
            self.firewall['showrules'] = self.config.get('firewall', 'SHOWRULES')
            self.firewall['printstatus'] = self.config.get('firewall', 'PRINTSTATUS')
            self.firewall['deftrust'] = self.config.get('firewall', 'DEFTRUST')
            self.firewall['deftargs'] = self.config.get('firewall', 'DEFTARGS')
            self.firewall['defexcld'] = self.config.get('firewall', 'DEFEXCLD')

    ALLOW_DHCP = '1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT'
    ALLOW_ICMP_8 = '1 -p icmp --icmp-type 8 -j ACCEPT'
    ALLOW_ICMP_0 = '1 -p icmp --icmp-type 0 -j ACCEPT'
    ALLOW_NET_ICMP_8 = '1 -d {net} -p icmp --icmp-type 8 -j ACCEPT'
    ALLOW_NET_ICMP_0 = '1 -d {net} -p icmp --icmp-type 0 -j ACCEPT'
    ALLOW_NET_ICMP = '1 -d {net} -p icmp -j ACCEPT'
    DISALLOW_DHCP = '1 -p udp --dport 67:68 --sport 67:68 -j DROP'
    DISALLOW_ICMP_8 = '1 -p icmp --icmp-type 8 -j DROP'
    DISALLOW_NET_ICMP = '1 -d {net} -p icmp -j DROP'

    # COLOR OUTPUT
    GREEN_PLUS = "[{green}+{endc}]".format(green=bcolors.OKGREEN, endc=bcolors.ENDC)
    OUTBOUND_C = "{obc}outbound{endc}".format(obc=bcolors.BOLD, endc=bcolors.ENDC)
    INBOUND_C = "{obc}outbound{endc}".format(obc=bcolors.BOLD, endc=bcolors.ENDC)

    def rule_builder(self, argument, append_rule=None, chain_options='iof'):
        chains = {'i': 'INPUT', 'o': 'OUTPUT', 'f': 'FORWARD'}
        if append_rule is not None:
            rule_list = ['iptables -{argument} {chain} {append_rule}'.format(chain=chains[i], argument=argument,
                                                                             append_rule=append_rule) for i in
                         chain_options]
        else:
            rule_list = ['iptables -{argument} {chain}'.format(chain=chains[i], argument=argument) for i in
                         chain_options]
        return rule_list

    def network_validator(self, network):
        try:
            ipaddr.IPNetwork(network)
        except Exception as e:
            raise Exception("Please validate your subnet. Valid input: 192.168.0.0/24")
        return True

    def data_validator(self, data):
        if type(data) == str:
            data = [data]
        elif type(data) == list:
            data = data
        return data

    def flush_rules(self):
        # Clear rules
        rules = self.rule_builder('F')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print('{gp} Rules Flushed!'.format(gp=self.GREEN_PLUS))
        return

    def set_policy(self, policy):
        # Set Policy for each chain
        rules = self.rule_builder('P', policy)
        self.command_list.extend(rules)
        return rules

    def set_defaults(self):
        self.set_policy('DROP')
        self.allow_related_conn()
        return

    def log_exceptions(self):
        rules = self.rule_builder('A', append_rule='-m limit --limit 5/min -j LOG')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print('{gp} Logging Exceptions'.format(gp=self.GREEN_PLUS))
        return rules

    def allow_localhost(self):
        rules = self.rule_builder('I', chain_options='io', append_rule='-s 127.0.0.1/8 -d 127.0.0.1/8 -j ACCEPT')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Allowing traffic for localhost.".format(gp=self.GREEN_PLUS))
        return

    def allow_all(self):
        # FLUSH RULES
        self.flush_rules()
        rules = self.set_policy('ACCEPT')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Allowing all...".format(gp=self.GREEN_PLUS))
        return

    def deny_all(self):
        # FLUSH RULES
        self.set_defaults()
        self.allow_localhost()
        if self.args.log_exceptions:
            self.log_exceptions()
        if self.verbose > 0:
            print("{gp} Disallowing all...".format(gp=self.GREEN_PLUS))
        return

    def allow_dhcp(self):
        rules = self.rule_builder('I', chain_options='io', append_rule=self.ALLOW_DHCP)
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Allowing DHCP...".format(gp=self.GREEN_PLUS))
        return

    def disallow_dhcp(self):
        rules = self.rule_builder('I', chain_options='io', append_rule=self.DISALLOW_DHCP)
        self.command_list.extend(rules)
        if self.verbose > 0:
            print(
            "{gp}{red} Disallowing {endc} DHCP...".format(gp=self.GREEN_PLUS, red=bcolors.FAIL, endc=bcolors.ENDC))
        return

    def all_icmp(self, status=1):
        if status == 0:
            rules = self.rule_builder('I', chain_options='o', append_rule=self.ALLOW_ICMP_8)
            rules += self.rule_builder('I', chain_options='o', append_rule=self.ALLOW_ICMP_0)
            self.command_list.extend(rules)
        else:
            rules = self.rule_builder('I', chain_options='o', append_rule=' 1 -p icmp -j ACCEPT')
            self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Allowing {outbound} ICMP...".format(gp=self.GREEN_PLUS, outbound=self.OUTBOUND_C))
        return

    def all_icmp_network(self, status=1, networks='0.0.0.0/0'):
        networks = self.data_validator(networks)
        try:
            for network in networks:
                self.network_validator(network)
                # STATUS 0 allows just Ping, set to 1 to allow ALL
                if status == 0:
                    rules = self.rule_builder('I', chain_options='o',
                                              append_rule=self.ALLOW_NET_ICMP_8.format(net=network))
                    rules += self.rule_builder('I', chain_options='o',
                                               append_rule=self.ALLOW_NET_ICMP_0.format(net=network))
                    self.command_list.extend(rules)
                else:
                    rules = self.rule_builder('I', chain_options='o',
                                              append_rule=self.ALLOW_NET_ICMP.format(net=network))
                    self.command_list.extend(rules)
                if self.verbose > 0:
                    print(
                    "{gp} Allowing {outbound} ICMP/traceroute to {net}...".format(net=network, outbound=self.OUTBOUND_C,
                                                                                  gp=self.GREEN_PLUS))
        except:
            raise Exception("[!] Could not parse subnet. Please ensure proper format: 192.168.0.0/24")
        return

    def allow_ping(self):
        rules = self.rule_builder('I', chain_options='i', append_rule=self.ALLOW_ICMP_8)
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Respond to pings...".format(gp=self.GREEN_PLUS))
        return

    def disallow_ping(self):
        rules = self.rule_builder('I', chain_options='i', append_rule=self.DISALLOW_ICMP_8)
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Disallowing incoming pings...".format(gp=self.GREEN_PLUS))
        return

    def set_nostrike(self, networks=[]):
        networks = self.data_validator(networks)
        if networks:
            rules = []
            for network in networks:
                rules += self.rule_builder('I', chain_options='i', append_rule='1 -s {net} -j DROP'.format(net=network))
                rules += self.rule_builder('I', chain_options='o', append_rule='1 -d {net} -j DROP'.format(net=network))
                if self.verbose:
                    print("{gp} {red}DISALLOWING{endr} traffic to {net} ".format(net=network, red=bcolors.FAIL,
                                                                                 endr=bcolors.ENDC, gp=self.GREEN_PLUS))
            self.command_list.extend(rules)
        return

    def reset_conn(self):
        rules = self.rule_builder('A', append_rule='-j REJECT')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Send tcp-reset for unwanted connections...".format(gp=self.GREEN_PLUS))
        return

    def allow_related_conn(self):
        rules = self.rule_builder('I', chain_options='io',
                                  append_rule=' 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        self.command_list.extend(rules)
        if self.verbose > 0:
            print("{gp} Allowing related connections...".format(gp=self.GREEN_PLUS))
        return

    def allow_outbound_transport(self, protocol='tcp', ports=[]):
        # TODO Maybe able to remove
        allowed_protocols = ['tcp', 'udp']
        if protocol not in allowed_protocols:
            raise Exception('[!] Protocol must be udp or tcp')
        if len(ports) == 0:
            rules = self.rule_builder('I', chain_options='o',
                                      append_rule='1 -p {protocol} -j ACCEPT'.format(protocol=protocol))
            self.command_list.extend(rules)
            if self.verbose > 0:
                print("{gp} Not limiting {outbound} {protocol} connections.".format(protocol=protocol.upper(),
                                                                                    gp=self.GREEN_PLUS,
                                                                                    outbound=self.OUTBOUND_C))
        else:
            ports = ','.join([str(p) for p in ports])
            rules = self.rule_builder('I', chain_options='o',
                                      append_rule='1 -p {protocol} -m multiport --dports {ports} -j ACCEPT'.format(
                                          ports=ports, protocol=protocol))
            self.command_list.extend(rules)
            if self.verbose > 0:
                print("[+] Limiting {outbound} connections to {protocol} ports: {ports}".format(ports=ports,
                                                                                                outbound=self.OUTBOUND_C,
                                                                                                protocol=protocol.upper()))
        return

    def allow_network_transport(self, direction=None, protocol='tcp', ports=[], networks='0.0.0.0', policy='ACCEPT'):
        if direction is None:
            raise Exception("[-] Must specify a direction!\nOptions: inbound, outbound")

        direction_map = {'inbound': 'i', 'outbound': 'o'}
        policy_accept = ['ACCEPT', 'DROP', 'REJECT']
        if policy not in policy_accept:
            raise Exception('Policy must be either ACCEPT, DROP or REJECT')

        allowed_protocols = ['tcp', 'udp']
        ports = ','.join([str(p) for p in ports])
        networks = self.data_validator(networks)

        if protocol not in allowed_protocols:
            raise Exception('[!] Protocol must be udp or tcp')
        try:
            if networks:
                for network in networks:
                    if len(ports) == 0:
                        rules = self.rule_builder('I', chain_options=direction_map[direction],
                                                  append_rule='1 -d {net} -p {protocol} -j {policy}'.format(
                                                      protocol=protocol, net=network, policy=policy))
                        self.command_list.extend(rules)
                        if self.verbose > 0:
                            print("{gp} Limiting {direction} {protocol} connections to {net}.".format(
                                protocol=protocol.upper(), gp=self.GREEN_PLUS,
                                direction=bcolors.BOLD + direction + bcolors.ENDC, net=network))
                    else:
                        rules = self.rule_builder('I', chain_options=direction_map[direction],
                                                  append_rule='1 -d {net} -p {protocol} -m multiport --dports {ports} -j {policy}'.format(
                                                      ports=ports, policy=policy, protocol=protocol, net=network))
                        self.command_list.extend(rules)
                        if self.verbose > 0:
                            if policy == 'DROP':
                                print(
                                    "{red} Disallowing{end} {direction} {protocol} connections to {net}  ports: {ports}".format(
                                        ports=ports, protocol=protocol.upper(),
                                        direction=bcolors.BOLD + direction + bcolors.ENDC, red=bcolors.FAIL,
                                        end=bcolors.ENDC, net=network))
                            print("{gp} Limiting {direction} {protocol} connections to {net}  ports: {ports}".format(
                                ports=ports, protocol=protocol.upper(),
                                direction=bcolors.BOLD + direction + bcolors.ENDC, gp=self.GREEN_PLUS, net=network))
        except Exception as e:
            raise Exception("[-] Rule could not be applied.\nReason: %s" % e)
        return

    def outbound_host(self):
        self.all_icmp()
        self.allow_outbound_transport(protocol='tcp')
        return

    def show_rules(self):
        self.it.run_command('iptables -nvL', VERBOSE=2)
        return

    def process_commands(self):
        if self.verbose:
            verbose = 2
        else:
            verbose = 0
        self.it.run_commands(self.command_list, VERBOSE=0)
        return
