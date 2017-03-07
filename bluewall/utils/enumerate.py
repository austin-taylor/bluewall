from bluewall.base.cli_parser import BsCli
from bluewall.base.validation import Validation
from bluewall.base.config import BWConfig
from bluewall.environment.rhel import config
from bluewall.utils.shell import Interact
from bluewall.utils.shell import bcolors
from bluewall.utils import ipaddr
from Queue import Queue
from threading import Thread
import subprocess
import random



class pingSweep(BsCli):
    def __init__(self, subnet=None, config_in=None, threads=4, shuffle=False, verbose=False):
        super(pingSweep, self).__init__(verbose=verbose)
        if subnet is not None:
            try:
                self.subnet_raw = subnet
                self.subnet = list(ipaddr.IPNetwork(subnet))
            except:
                raise Exception('Please ensure your subnet is in proper format: 192.168.1.0/24')
        # TODO ADD NOSTRIKE AND MAKE OUTPUT FOR SCANNER NESSUS COMPATIBLE (IP,\n,IP)
        self.threads = threads
        self.queue = Queue()
        self.alive = 0
        self.alive_hosts = []
        self.shuffle = random
        self.it = Interact()
        self.root_check = self.it.root_check(debug=False)
        self.parse_args()
        self.config_in = config_in
        self.shuffle = shuffle
        self.verbose=verbose

        print config_in
        if config_in is not None:
            self.configs = config(config=config_in, VERBOSE=self.verbose)
            #Validation(config_in, verbose=self.verbose).validate()
            self.target_ranges = self.configs.configs.get('target_range', '')
            self.trusted_range = self.configs.configs.get('trusted_range', '')
            self.nostrike = self.configs.configs.get('nostrike', '')
        else:
            #print("[-] Please specify a configuration path!")
            self.nostrike = None


        self.GREEN_PLUS = "[{green}+{endc}]".format(green=bcolors.OKGREEN, endc=bcolors.ENDC)
        self.WARN = "[{red}!{endc}]".format(red=bcolors.WARNING, endc=bcolors.ENDC)
        self.INFO = "[{obc}INFO{endc}]".format(obc=bcolors.OKBLUE, endc=bcolors.ENDC)

    def shuffle_host(self):
        random.shuffle(self.subnet)
        return self.subnet

    def pinger(self, i, q):
        """PING SUBNET"""
        nostrike = None
        # ACCOUNTS FOR IPS IN NO STRIKE -- THEY WILL NOT BE TOUCHED
        if self.nostrike:
            nostrike = [str(x) for b in self.nostrike for x in ipaddr.IPNetwork(b)]

        while True:
            ip = q.get()
            if nostrike and ip not in nostrike:
                ret = subprocess.call("ping -c 1 %s" % ip,
                                  shell=True,
                                  stdout=open('/dev/null', 'w'),
                                  stderr=subprocess.STDOUT)

                if ret == 0:
                    print('{gp} {ip} is alive'.format(gp=self.GREEN_PLUS, ip=str(ip)))
                    self.alive += 1
                    self.alive_hosts.append(str(ip))
                q.task_done()
        return

    # Spawn thread pool
    def thread_pool(self):
        for i in range(self.threads):
            worker = Thread(target=self.pinger, args=(i, self.queue))
            worker.setDaemon(True)
            worker.start()
        return

    def queue_workers(self):
        for ip in self.subnet:
            self.queue.put(ip)
        return

    def get_alive(self):
        if self.shuffle:
            self.shuffle_host()

        self.thread_pool()
        self.queue_workers()
        print(str('{info} Processing {subnet_length} hosts for {subnet} using {x} threads'.format(info=self.INFO, subnet=self.subnet_raw, subnet_length=len(self.subnet), x=self.threads)))
        self.queue.join()
        if self.verbose and self.alive:
            print(str("{gp} {alive} alive hosts in subnet".format(alive=self.alive, gp=self.INFO)))
        if self.verbose and not self.alive:
            print(str("{rm} {alive} alive hosts in subnet".format(alive=self.alive, rm=self.WARN)))
        return self.alive_hosts

# ALLOW PING BY DEFAULT
#ps = pingSweep(subnet='172.16.63.0/24', config_in='/home/assessor/PycharmProjects/bluewall/configs/exampleconfig.ini', shuffle=True)