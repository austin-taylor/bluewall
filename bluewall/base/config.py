import bluewall.utils.configparser as cp
from collections import OrderedDict

class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(OrderedDict, self).__setitem__(key, value)


class BWConfig(object):
    def __init__(self, config_in=None):
        self.config_in = config_in
        self.config = cp.RawConfigParser(dict_type=MultiOrderedDict)
        self.config.read(self.config_in)

    def get(self, section, option):
        return self.config.get(section, option)