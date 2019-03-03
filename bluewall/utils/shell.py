import subprocess
import os
from bluewall.utils.whiptail import Whiptail

class Interact(object):
    def run_command(self, cmd, VERBOSE=0, DEBUG=False, wait=False):
        if VERBOSE < 2:
            cmd += " 2>/dev/null"
        if DEBUG or VERBOSE > 1:
            print "$ " + cmd
        if wait:
            output = subprocess.Popen(cmd, shell=True)
            output.wait()
        else:
            output = subprocess.check_output(cmd, shell=True)
        if DEBUG or VERBOSE > 1:
            print output
        return output

    def run_commands(self, cmd_list, VERBOSE=0, DEBUG=False):
        # Takes a list of commands to run
        for cmd in cmd_list:
            self.run_command(cmd, VERBOSE=VERBOSE, DEBUG=DEBUG)
        return

    def demand_input(self, prompt):
        response = ""
        while response is "":
            response = raw_input(prompt).strip()
        return response

    def root_check(self, debug=False):
        if debug:
            print 'UID: ' + str(os.getuid())
        if os.getuid() != 0:
            print("[-] Program MUST be run as sudo or root!\nUsage: sudo bw <options>")
            exit()
        return

    def get_rhel_eth_ifaces(self):
        return [iface for iface in Interact().run_command("nmcli d | cut -d' ' -f 1").split('\n')[1:] if iface != '']
    
    def get_config_whiptail(self, DEBUG=False):
        from bluewall.base.validation import Validation
        validator = Validation()
        whip = Whiptail(title="Bluewall Wizard")

        all_ifaces = self.get_rhel_eth_ifaces()
        iface = whip.radiolist('Ethernet interface (press <space> to select): ', items=all_ifaces)[0]

        local_config_fields = [
            #('iface', 'RedHat ethernet interface', 1, 1, [validator.eth_iface_check]),
            ('rh_host', 'RedHat hostname', 1, 1, [validator.hostname_check]),
            ('rh_ipaddr', 'RedHat IP Address', 1, 1, [validator.ip_validator]),
            ('netmask', 'Network Mask', 1, 1, [validator.ip_validator]),
            ('gateway_addr', 'Gateway Address', 1, 1, [validator.ip_validator]),
            ('rh_mac', 'MAC Address (enter * for random)', 1, 1, [validator.mac_check])
        ]

        firewall_config_fields = [
            ('target_range', 'Target range (enter blank when finished)', 0, 100, [validator.network_validator]),
            ('target_host', 'Target host (enter blank when finished)', 0, 100, [validator.ip_validator]),
            ('trusted_range', 'Trusted range (enter blank when finished)', 0, 100, [validator.network_validator]),
            ('trusted_host', 'Trusted host (enter blank when finished)', 0, 100, [validator.ip_validator]),
            ('nostrike', 'No-strike range (enter blank when finished)', 0, 100, [validator.network_validator])
        ]

        if DEBUG:
            print "Getting config via whiptail"

        config_builder = []
        config_builder.append('[local_config]\n')
        config_builder.append('iface='+iface+'\n')
        for (field_name, friendly_name, min_entries, max_entries, validators) in local_config_fields:
            for x in xrange(1, max_entries+1):
                mandatory = True
                if x > min_entries:
                    mandatory = False
                user_input = self.demand_whiptail_input(whip, friendly_name, validators, mandatory)
                if user_input == '':
                    break
                config_builder.append(field_name + '=' + user_input + '\n')

        config_builder.append('\n[firewall_config]\n')
        for (field_name, friendly_name, min_entries, max_entries, validators) in firewall_config_fields:
            for x in xrange(1, max_entries+1):
                mandatory = True
                if x > min_entries:
                    mandatory = False
                user_input = self.demand_whiptail_input(whip, friendly_name, validators, mandatory)
                if user_input == '':
                    break
                config_builder.append(field_name + '=' + user_input + '\n')

        error_input = ''
        while True:
            msg = error_input + "Enter a filename to output config: "
            try:
                config_filename = self.get_whiptail_input(whip, msg)
                with open(config_filename, 'w') as config_file:
                    config_file.writelines(config_builder)
                break
            except IOError:
                error_input = "Invalid filename.\n\n"
                continue

        config_text = ''.join(config_builder)

        if whip.confirm("Would you like to view your config?", default='yes'):
            whip.alert_large(config_text, height=30)

        whip.set_title("Bluewall: " + config_filename)
        if whip.confirm("Would you like to execute Bluewall with this config now?", default='no'):
            self.run_command('bw -c ' + config_filename, VERBOSE=2)

        # escape all other bw function for this instance
        exit()


    def get_whiptail_input(self, whip, msg):
        return whip.prompt(msg)

    def demand_whiptail_input(self, whip, msg, validator_callbacks, mandatory=True):
        user_input = None
        error_input = ''
        while True:
            user_input = whip.prompt(error_input + msg)
            if user_input.strip() == '' and mandatory == False:
                return ''
            for callback in validator_callbacks:
                if callback(user_input):
                    return user_input
            error_input = "Your entry was invalid.\n\n"
        return None

class bcolors:
    HEADERS = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
