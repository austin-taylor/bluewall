import os
import json

class AOR(object):
    """
    CONFIG PARSER: Takes in file and parses it out.
    TARGET: Parses out target host from config
    TRUSTED: Parses trusted host from config
    NOSTRIKES: Parses no strikes from config
    """

    def __init__(self, config=None, DEBUG=False, VERBOSE=False):

        self.verbose = VERBOSE
        self.debug = DEBUG

        if config is None:
            raise Exception("[-] Cannot continue without config!")
        else:
            self.configs = self.get_config_from_file(config)
            if self.debug:
                print self.configs

    def get_config_from_file(self, config_path, write_json=False, json_out='config.json'):
        if self.debug:
            print "{config_path}: ".format(config_path=config_path),
        if not os.path.isfile(config_path):
            if self.verbose:
                print "getting config from wizard"
            return

        with open(config_path, 'r') as infile:
            rawconfigs = infile.readlines()

        configs = dict()
        configs['trusted_range'] = []
        configs['trusted_host'] = []
        configs['target_range'] = []
        configs['target_host'] = []
        configs['nostrike_range'] = []
        configs['nostrike_host'] = []

        for line in rawconfigs:
            try:
                if line.strip()[:1] is '#':
                    continue
                k, v = line.strip().split("=")
            except ValueError:
                continue
            k = k.lower()
            if self.debug:
                print k, v
            try:
                configs[k].append(v)
            except KeyError:
                configs[k] = []
                configs[k].append(v)
        if self.debug:
            print configs

        if write_json:
            try:
                with open(json_out, 'w') as json_out_file:
                    json.dump(configs, json_out_file, sort_keys=True, indent=4, separators=(',', ': '))
            except:
                self.log_error("Saving to JSON output failed.")

        return configs

    def target_parser(self, path):
        """ Process targets """
        target_file = None
        try:
            target_file = open(path, 'w')
        except:
            self.log_error("{path} not available for write access.", path=path)

        if target_file:
            try:
                for target_range in self.configs['target_range']:
                    if self.verbose:
                        print "Adding target range:\t" + target_range
                    target_file.write(target_range + '\n')
            except:
                if self.verbose:
                    print "No target ranges set in " + path
            try:
                for target_host in self.configs['target_host']:
                    if self.verbose:
                        print "Adding target host:\t" + target_host
                    target_file.write(target_host + '\n')
            except:
                if self.verbose:
                    print "No target hosts set in " + path
        return

    def trusted_parser(self, path):
        """ process trusted hosts """
        try:
            trusted_file = open(path, 'w')
        except:
            self.log_error("{path} not available for write access.".format(path=path))

        if trusted_file:
            try:
                for trusted_range in self.configs['trusted_range']:
                    if self.verbose:
                        print "Adding trusted range:\t" + trusted_range

                    if self.legacy:
                        trusted_file.write(trusted_range + '\n')
            except:
                if self.verbose:
                    print "No trusted ranges set in " + path

            try:
                for trusted_host in self.configs['trusted_host']:
                    if self.verbose:
                        print "Adding trusted host:\t" + trusted_host
                    if self.legacy:
                        trusted_file.write(trusted_host + '\n')
            except:
                if self.verbose:
                    print "No trusted hosts set in " + path

            try:
                win_ipaddr = self.configs['win_ipaddr'][0]
                print "Adding Win IP as trusted host:\t" + win_ipaddr
                if self.legacy:
                    trusted_file.write(win_ipaddr + '\n')
            except:
                pass
        return

    def nostrikes_parser(self, path):
        """ process nostrikes """
        try:
            nostrikes_file = open(path, 'w')
        except:
            self.log_error("{path} not available for write access.".format(path=path))

        if nostrikes_file:
            try:
                for nostrike in self.configs['nostrike']:
                    if self.legacy:
                        nostrikes_file.write(nostrike + '\n')

            except:
                if self.verbose:
                    print "No NOSTRIKE set in " + path
        return
