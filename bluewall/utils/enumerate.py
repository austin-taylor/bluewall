import ipaddr
import subprocess
import random
from Queue import Queue
from threading import Thread


class pingSweep(object):
    def __init__(self, subnet=None, threads=4, shuffle=False):
        if subnet is not None:
            try:
                self.subnet = list(ipaddr.IPNetwork(subnet))
            except:
                raise Exception('Please ensure your subnet is in proper format: 192.168.1.0/24')

        self.threads = threads
        self.queue = Queue()
        self.alive = 0
        self.alive_hosts = []
        self.shuffle = random

    def shuffle_host(self):
        random.shuffle(self.subnet)
        return self.subnet

    def pinger(self, i, q):
        """PING SUBNET"""
        while True:
            ip = q.get()
            ret = subprocess.call("ping -c 1 %s" % ip,
                                  shell=True,
                                  stdout=open('/dev/null', 'w'),
                                  stderr=subprocess.STDOUT)

            if ret == 0:
                print str(ip) + ' is alive'
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
        print(str('Processing {subnet_length} hosts'.format(subnet_length=len(self.subnet))))
        self.queue.join()
        print(str("{alive} alive hosts in subnet".format(alive=self.alive)))
        return self.alive_hosts

alive_hosts = pingSweep(subnet='192.168.0.0/24', threads=10, shuffle=False)



#alive_hosts.get_alive()
