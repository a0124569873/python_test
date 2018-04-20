# Copyright 2014, 6WIND S.A.

import fnmatch
import os
import re

from fp_conf_tools import pci_card, util


# --------------------------- globals and define -------------------------------

_QUAD_ARCHI = [
    'Intel(R) Xeon(R) CPU E5-*',
    'Intel(R) Xeon(R) CPU E7-*',
    'Intel(R) Core(TM) i7-5960X*',
    'Intel(R) Core(TM) i7-5930K*',
    'Intel(R) Core(TM) i7-5820K*',
    'Intel(R) Core(TM) i7-4960X*',
    'Intel(R) Core(TM) i7-4930K*',
    'Intel(R) Core(TM) i7-4820K*',
    'Intel(R) Core(TM) i7-3970X*',
    'Intel(R) Core(TM) i7-3960X*',
    'Intel(R) Core(TM) i7-3930K*',
    'Intel(R) Core(TM) i7-3820*'
]

_TRIPLE_ARCHI = [
    'Intel(R) Xeon(R) CPU E55?? Nehalem-EP*',
    'Intel(R) Xeon(R) CPU E56?? Westmere-EP*',
    'Intel(R) Xeon(R) CPU EC???? Jasper Forest*',
    'Intel(R) Xeon(R) CPU L55?? Nehalem-EP*',
    'Intel(R) Xeon(R) CPU L5609 Westmere-EP*',
    'Intel(R) Xeon(R) CPU L5630 Westmere-EP*',
    'Intel(R) Xeon(R) CPU L5640 Westmere-EP*',
    'Intel(R) Xeon(R) CPU LC55x8 Jasper Forest*',
    'Intel(R) Xeon(R) CPU W???? Bloomfield, Nehalem-EP, Westmere-EP*',
    'Intel(R) Xeon(R) CPU X55?? Nehalem-EP*',
    'Intel(R) Xeon(R) CPU X56?? Westmere-EP*',
    'Intel(R) Core(TM) i7-9?? Bloomfield, Gulftown*',
    'Intel(R) Core(TM) i7-9?0? Gulftown*'
]

_HUGEPAGES = '/sys/devices/system/node/node%d/hugepages'
_FREE_HUGEPAGES = os.path.join(_HUGEPAGES, '%s/free_hugepages')
_NODE_OF_LCORE_ID = '/sys/devices/system/cpu/cpu%d'
_PCIBUS_PATH = '/sys/bus/pci/devices/%s'
_PCI_NOT_SUPPORTED = '\tUnsupported %s PCI card: %s (present on bus %s)\n'

CPUINFO_RE = re.compile(r'processor\s+:\s+(\d+).*?' +
                        r'model name\s+:\s+(.*?)stepping.*?' +
                        r'physical id\s+:\s+(\d+).*?' +
                        r'core id\s+:\s+(\d+).*?' +
                        r'flags\s+:\s+(.*?)bogomips', re.DOTALL)

PCIINFO_RE = re.compile(r'''
(?P<bus>[A-Fa-f0-9]{4}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}.[0-9]{1}) # bus address
\s+
(?P<class_id>0200|0b40|1000):      # device class 0200 for network, 0b40 or 1000 for crypto
\s+
(?P<vendor_id>[A-Fa-f0-9]{4})      # vendor id
:
(?P<product_id>[A-Fa-f0-9]{4})     # product id
''', re.VERBOSE)


# --------------------------- main class ---------------------------------------

class MachineDescription(object):

    def __init__(self):
        self.cpu_info = CpuInfo()
        self.pci_network = {}
        self.pci_network_count = 0
        self.pci_crypto = {}
        self.pci_crypto_count = 0
        self.pci_not_supported = {}
        self.pci_not_supported_count = 0
        self.nb_txd = -1
        self.nb_rxd = -1
        self.addon_options = []
        self.eal_options = []
        self.fpnsdk_options = []
        self.fp_options = []

    def __str__(self):
        machine_txt = str(self.cpu_info)

        for sock_id, socket in self.cpu_info.sockets.iteritems():
            machine_txt += '\n' + '-' * 100 + '\n\t\tsocket %d\n' % sock_id
            machine_txt += str(socket)
            machine_txt += '\n\nEthernet PCI information:\n'
            for pci in self.pci_network.itervalues():
                if pci.numa_node == sock_id:
                    machine_txt += str(pci)

            machine_txt += '\n\nAvailable crypto:\n'
            for crypto in self.pci_crypto.itervalues():
                if crypto.numa_node == sock_id:
                    machine_txt += str(crypto)

            machine_txt += '\n\nUnsupported PCI cards:\n'
            for pci in self.pci_not_supported.itervalues():
                if pci.numa_node == sock_id:
                    machine_txt += str(pci)

        return machine_txt.rstrip()

    def _add_crypto_card(self, driver_name, bus, node, card):
        reg_ref = self._get_link_crypto_card(card)
        new_crypto = PCIGeneric(driver_name, bus=bus, numa_node=node,
                                info=PCICrypto(card))
        if reg_ref != -1:
            new_crypto.info.linked_ref = reg_ref
            ref_crypto = self.pci_crypto[reg_ref]
            ref_crypto.info.link_key.append(self.pci_crypto_count)
        self.pci_crypto[self.pci_crypto_count] = new_crypto
        self.pci_crypto_count += 1

    def _add_network_card(self, driver_name, bus, node, card):
        eth_path = util.find(_PCIBUS_PATH % bus, 'net')
        new_network = PCIGeneric(driver_name, bus=bus, numa_node=node,
                                 info=PCINetwork(card))

        if eth_path:
            new_network.info.eth = _eth_name(eth_path)
            max_rxq = 0
            max_txq = 0
            for f in os.listdir('%s/%s/queues' % (eth_path,
                                                  new_network.info.eth)):
                if f.startswith('rx-'):
                    max_rxq += 1
                if f.startswith('tx-'):
                    max_txq += 1
            new_network.info.max_rxq = max_rxq
            new_network.info.max_txq = max_txq

        # if card capabilities is fixed override read value
        if card.capabilities:
            new_network.info.max_rxq = card.capabilities.rxq
            new_network.info.max_txq = card.capabilities.txq

        self.pci_network[self.pci_network_count] = new_network
        self.pci_network_count += 1

    def _add_read_core_port(self, core, sel_port):
        cur_port = 0
        errors = ''

        for pci_id, pci in self.pci_network.iteritems():
            if pci.info.status:
                if cur_port == sel_port:
                    if not core in pci.info.used_cpu:
                        socket = self.cpu_info.sockets[pci.numa_node]
                        if not socket.add_core_info(core, pci_id):
                            errors += 'ERROR: try to add a non valid core (%d) for the PCI card on bus %s\n' % (core, pci.bus)
                        else:
                            pci.info.used_cpu.append(core)
                    return errors
                else:
                    cur_port += 1
        return errors

    def _get_link_crypto_card(self, card):
        for crypto_id, crypto in self.pci_crypto.iteritems():
            if crypto.info.card == card:
                return crypto_id
        return -1

    def _get_numa_node(self, bus):
        if self.cpu_info.thread_count == 1:
            return 0

        # do not read /sys/bus/pci/devices/%pcieth.bus/numa_node (not always valid)
        with open('/sys/bus/pci/devices/%s/local_cpulist' % bus, 'r') as f:
            local_cpulist = f.read()

        cpulist = util.get_cpu_list(local_cpulist.rstrip(), [])
        node_number = -1
        if len(cpulist):
            for socket_id, socket in self.cpu_info.sockets.iteritems():
                if cpulist[0] in socket.htread_list:
                    if set(cpulist).issubset(set(socket.htread_list)) == True:
                        # local cpulist information is correct, use it
                        node_number = socket_id
                    else:
                        # bios issue. Used bus info to retrieve socket
                        pci_info = bus.rsplit(':')
                        if self.cpu_info.socket_count == 2:
                            node_number = (int(pci_info[1], 16) & 128) >> 7
                        if self.cpu_info.socket_count == 4:
                            node_number = (int(pci_info[1], 16) & 192) >> 6
                        if self.cpu_info.socket_count == 8:
                            node_number = (int(pci_info[1], 16) & 224) >> 5
                    break

        return node_number

    def _set_allpci_state(self, state):
        for pci in self.pci_network.itervalues():
            pci.info.status = state

    def _set_pci_off_by_name(self, eth_name):
        for pci in self.pci_network.itervalues():
            if pci.info.eth == eth_name:
                pci.info.status = 0
                return

    def _set_pci_state_by_bus(self, state, bus):
        for pci in self.pci_network.itervalues():
            if pci.bus == bus:
                pci.info.status = state
                return

    def numa_node(self, pci_nb):
        return self.pci_network[pci_nb].numa_node

    def available_cpu(self, pci_nb):
        node = self.numa_node(pci_nb)
        return self.cpu_info.sockets[node].htread_list

    def get_network_name(self, pci_nb):
        return self.pci_network[pci_nb].driver_name

    def get_network_eth(self, pci_nb):
        return self.pci_network[pci_nb].info.eth

    def get_network_state(self, pci_nb):
        return self.pci_network[pci_nb].info.status

    def get_network_used_cpu(self, pci_nb):
        return self.pci_network[pci_nb].info.used_cpu

    def cpu_update(self, pci_nb, new_list):
        socket_id = self.pci_network[pci_nb].numa_node
        old_list = self.pci_network[pci_nb].info.used_cpu
        to_add = list(set(new_list)-set(old_list))
        to_remove = list(set(old_list)-set(new_list))
        socket = self.cpu_info.sockets[socket_id]

        for add_core_nb in to_add:
            socket.add_core_info(add_core_nb, pci_nb)

        for rm_core_nb in to_remove:
            socket.remove_core_info(rm_core_nb, pci_nb)

        self.pci_network[pci_nb].info.used_cpu = new_list
        if new_list:
            self.pci_network[pci_nb].info.status = 1
        else:
            self.pci_network[pci_nb].info.status = 0

    def read_cpu_info(self):
        cpuname = 'Unknown'
        flags = ''

        with open('/proc/cpuinfo', 'r') as f:
            buf = f.read()

        for match in CPUINFO_RE.finditer(buf):
            cpuname = match.group(2)
            flags = match.group(5)

            core_id = int(match.group(4))
            hyperthread_id = int(match.group(1))

            socket_id = _node_for_lcore(hyperthread_id)
            if socket_id == -1:
                print ('sys/devices/system/cpu/cpu%d have no reference to a socket.'
                       % hyperthread_id)
                socket_id = int(match.group(3))

            if not socket_id in self.cpu_info.sockets:
                self.cpu_info.sockets[socket_id] = Socket()
                self.cpu_info.socket_count += 1
                self.cpu_info.sockets[socket_id].freehugepage = _free_hugepages(socket_id)
            socket = self.cpu_info.sockets[socket_id]

            if not core_id in socket.cores:
                socket.cores[core_id] = Core()
                socket.free_cores.append(core_id)
                self.cpu_info.core_count += 1
            core = socket.cores[core_id]

            if not hyperthread_id in core.hyperthreads:
                core.hyperthreads[hyperthread_id] = HThread()
                socket.htread_list.append(hyperthread_id)

            self.cpu_info.thread_count += 1

        self.cpu_info.mem_channel = _get_memory_channel(cpuname)
        self.cpu_info.name = cpuname.rstrip()

        # Add crypto multibuffer fo Intel card with aes and (avx or avx2 or sse) flags present
        if ((cpuname.rfind('Intel(R)') != -1) and (flags.rfind('aes') != -1) and
                ((flags.rfind('avx') != -1) or (flags.rfind('sse') != -1))):
            card = pci_card.find_card_family('8086', 'ffff')
            for i in range(0, self.cpu_info.socket_count):
                self._add_crypto_card('Intel Multibuffer', '', i, card)

    def read_pci_info(self):
        buf = util.lspci('-nD')

        for match in PCIINFO_RE.finditer(buf):
            vendor_id = match.group('vendor_id')
            product_id = match.group('product_id')
            class_id = match.group('class_id')
            bus = match.group('bus')

            driver_name = _read_driver_name(bus, class_id)
            node = self._get_numa_node(bus)
            try:
                card = pci_card.find_card_family(vendor_id, product_id)
            except:
                card = None

            if card:
                if class_id == '0200':
                    self._add_network_card(driver_name, bus, node, card)
                else:
                    self._add_crypto_card(driver_name, bus, node, card)
            else:
                class_name = 'Crypto'
                if class_id == '0200':
                    class_name = 'Network'
                unk_pci = PCIGeneric(driver_name, bus=bus, numa_node=node,
                                     info=PCINotSupported(class_name,
                                                          vendor_id,
                                                          product_id))
                self.pci_not_supported[self.pci_not_supported_count] = unk_pci
                self.pci_not_supported_count += 1

    def show(self):
        print 'Fast path configuration info'
        print '============================\n'
        has_eth_selected = False
        for pci in self.pci_network.itervalues():
            if pci.info.used_cpu:
                if has_eth_selected == False:
                    has_eth_selected = True
                    print '  Selected ethernet card'
                    print '  ----------------------\n'
                name = pci.driver_name
                eth = pci.info.eth
                cpulist = util.cpu_list_to_string(pci.info.used_cpu)
                if eth == 'none':
                    mount_info = '(not mounted on any eth) '
                else:
                    mount_info = 'mounted on %s ' % eth
                print '  %s PCI card %s with cores %s' % (name, mount_info,
                                                          cpulist)
        if has_eth_selected == False:
            print 'WARNING: No ethernet card has been selected'

        has_crypto_selected = False
        for crypto in self.pci_crypto.itervalues():
            if crypto.info.status:
                if has_crypto_selected == False:
                    has_crypto_selected = True
                    print '\n  Used cryptographic hardware accelerator'
                    print '  ---------------------------------------\n'
                print '  %s' % crypto.info.card.name
        print

    def update_with_config(self, fp_param, fp_mem):
        """
        :arg FastpathParameter fp_param:
            dfkls jlkdf jglkdfgjldfk gjkldfjg
        :arg FastPathMemory fp_mem:
            Lfj ldfkjlkdfj glkdfjglkd fjglkdfj
        """
        errors = ''

        if fp_param.whitelist and (fp_param.blacklist or fp_param.ignore_netdev):
            #TODO: errors.append(ConfigError('cannot use whitelist and blacklist'))
            return errors

        if fp_param.blacklist or fp_param.ignore_netdev:
            self._set_allpci_state(1)
            for net in fp_param.ignore_netdev:
                self._set_pci_off_by_name(net)
            for b_pci in fp_param.blacklist:
                self._set_pci_state_by_bus(0, b_pci)

        if len(fp_param.whitelist):
            for w_pci in fp_param.whitelist:
                self._set_pci_state_by_bus(1, w_pci)

        # Update crypto card info
        for add_on in fp_param.addonlibrary:
            for pci in self.pci_crypto.itervalues():
                crypto = pci.get_crypto()
                if ((add_on in crypto.card.required_addons) and
                        crypto.can_be_selected()):
                    crypto.toggle_info(fp_mem, [])

        #Update cpu selection per port
        core_mapping_list = fp_param.coremask.rsplit('/')
        for core_mapping in core_mapping_list:
            info = core_mapping.rsplit('=')
            core = int(info[0][1:])
            port_list = info[1].rsplit(':')
            for port in port_list:
                errors += self._add_read_core_port(core, int(port))

        self.cpu_info.mem_channel = fp_param.memchannel


        self.addon_options = fp_param.addonlibrary
        self.eal_options = fp_param.additional_eal_options
        self.fpnsdk_options = fp_param.additional_fpnsdk_options
        self.fp_options = fp_param.additional_fp_options
        self.nb_txd = fp_param.nbtxd
        self.nb_rxd = fp_param.nbrxd

        return errors

    def clean_config(self):
        for pci in self.pci_network.itervalues():
            if pci.info.status:
                if not pci.info.used_cpu:
                    pci.info.status = 0

# --------------------------- subclasses ---------------------------------------

class PCIGeneric(object):

    def __init__(self, driver_name, numa_node=None,
                 bus=None, info=None):
        self.driver_name = driver_name
        self.bus = bus or ''
        self.numa_node = numa_node or 0
        self.info = info

    def __str__(self):
        return self.info.display(self.driver_name, self.bus)

    def get_bus(self):
        return self.bus

    def get_crypto(self):
        return self.info

class PCICrypto(object):

    def __init__(self, card):
        self.card = card
        self.status = 0
        self.link_key = []
        self.linked_ref = -1

    def display(self, driver_name, bus):
        if bus != '':
            pci_txt = '\t%s (present on bus %s)\n' % (driver_name, bus)
        else:
            pci_txt = '\t%s\n' % driver_name

        return pci_txt

    def get_crypto_name(self):
        return self.card.name

    def can_be_selected(self):
        if self.linked_ref == -1:
            return True
        return False

    def is_selected(self):
        if self.status:
            return True
        return False

    def toggle_info(self, fp_mem, addon_options):
        name = self.card.capabilities.option_name
        if self.status:
            self.status = 0
            fp_mem.remove_memory(name + '_pool')
            fp_mem.remove_memory(name + '_session')
            fp_mem.remove_memory(name + '_context')
            pmd_list = self.card.required_addons
            for pmd in pmd_list:
                if pmd in addon_options:
                    addon_options.remove(pmd)
        else:
            self.status = 1
            fp_mem.add_memory(name + '_pool', False,
                              fp_mem.crypto_buffers_nb,
                              self.card.capabilities.pool_size,
                              True)
            fp_mem.add_memory(name + '_session', False,
                              fp_mem.crypto_session_nb,
                              self.card.capabilities.session_size,
                              False)
            fp_mem.add_memory(name + '_context', False,
                              fp_mem.crypto_session_nb,
                              self.card.capabilities.context_size,
                              True)

class PCINetwork(object):

    def __init__(self, card=None):
        self.card = card
        self.status = 0
        self.used_cpu = []
        self.max_rxq = -1
        self.max_txq = -1
        self.eth = 'none'

    def display(self, driver_name, bus):
        pci_txt = ''
        if self.eth == 'none':
            pci_txt += '\t%s not mounted on any eth' % driver_name
        else:
            pci_txt += '\t%s mounted on %s' % (driver_name, self.eth)
        pci_txt += ' (present on bus %s)' % bus
        if self.max_rxq == -1:
            pci_txt += ' with unknown max rxq/txq\n'
        else:
            pci_txt += '  with max rxq/txq : %d / %d\n' % (self.max_rxq,
                                                           self.max_txq)
        return pci_txt

class PCINotSupported(object):

    def __init__(self, class_name, vendor_id, product_id):
        self.class_name = class_name
        self.vendor_id = vendor_id
        self.product_id = product_id

    def display(self, driver_name, bus):
        pci_txt = _PCI_NOT_SUPPORTED % (self.class_name, driver_name, bus)

        return pci_txt

class CpuInfo(object):

    def __init__(self):
        self.sockets = {}
        self.name = ''
        self.mem_channel = -1
        self.socket_count = 0
        self.core_count = 0
        self.thread_count = 0

    def __str__(self):
        cpu_txt = 'General information\n'
        cpu_txt += '\tProcessor name: %s\n' % self.name
        cpu_txt += '\tSockets %d, Cores %d, Hyperthreads %d\n' % (self.socket_count,
                                                                  self.core_count,
                                                                  self.thread_count)
        if self.mem_channel != -1:
            cpu_txt += '\tMulti channel memory architecture: %d channels\n' % self.mem_channel
        else:
            cpu_txt += '\tMulti channel memory architecture is unknown\n'
        return cpu_txt

class Socket(object):

    def __init__(self):
        self.cores = {}
        self.freehugepage = 0
        self.eth_list = []
        self.htread_list = []
        self.free_cores = []
        self.used_cores = []      # cores used by FP

    def __str__(self):
        count = 0
        socket_txt = '\t\t--------\n'
        socket_txt += 'Memory information\n'
        socket_txt += '\tFree huge pages: %d\nCores list:\n' % self.freehugepage
        for core_id, core in self.cores.iteritems():
            if count != 3:
                socket_txt += '\tCore %3d = [%s]' % (core_id, str(core))
                count += 1
            else:
                socket_txt += '\tCore %3d = [%s]\n' % (core_id, str(core))
                count = 0
        return socket_txt.rstrip()

    def add_core_info(self, core_nb, port_nb):
        for coreid, core in self.cores.iteritems():
            if core_nb in core.hyperthreads:
                core.hyperthreads[core_nb].state = 1
                core.hyperthreads[core_nb].port.append(port_nb)
                if not coreid in self.used_cores:
                    self.used_cores.append(coreid)
                    pos = self.free_cores.index(coreid)
                    self.free_cores.pop(pos)
                return True
        return False

    def remove_core_info(self, core_nb, port_nb):
        for coreid, core in self.cores.iteritems():
            if core_nb in core.hyperthreads:
                pos = core.hyperthreads[core_nb].port.index(port_nb)
                core.hyperthreads[core_nb].port.pop(pos)
                if core.hyperthreads[core_nb].port:
                    core.hyperthreads[core_nb].state = 0
                    change = True
                    for hthread in core.hyperthreads.itervalues():
                        if len(hthread.port):
                            change = False
                    if change:
                        self.free_cores.append(coreid)
                        pos = self.used_cores.index(coreid)
                        self.used_cores.pop(pos)
                return


class Core(object):

    def __init__(self):
        self.hyperthreads = {}

    def __str__(self):
        core_txt = ''
        for htread_id in self.hyperthreads.iterkeys():
            core_txt += '-%3d' % htread_id

        return core_txt[1:]


class HThread(object):

    def __init__(self):
        self.state = 0   # 0 free, 1 used by FP and can listen to only one port, 2 used by FP and can listen to several ports
        self.port = []   # list of ports listening by the hyperthread

# --------------------------- private functions --------------------------------

def _read_driver_name(bus, class_id):
    """
    Return name of a PCI card
    """
    full_name = util.lspci('-D -s%s' % bus)
    if class_id == '1000':
        cardname = full_name.rsplit('device: ')
    elif class_id == '0b40':
        cardname = full_name.rsplit('processor: ')
    else:
        cardname = full_name.rsplit('controller: ')

    if len(cardname) == 2:
        return cardname[1].rstrip()
    else:
        return full_name.rstrip()

def _get_memory_channel(cpu_name):
    """
    Get memory channel architecture of the system.
    Retrun -1 if architecture can not be found
    """
    for arch in _QUAD_ARCHI:
        if fnmatch.fnmatch(cpu_name, arch):
            return 4

    for arch in _TRIPLE_ARCHI:
        if fnmatch.fnmatch(cpu_name, arch):
            return 3

    return -1

def _free_hugepages(socket_id):
    """
    Get size of free hugepages of a node
    """
    free_size = 0
    for f in os.listdir(_HUGEPAGES % socket_id):
        if not f.startswith('hugepages-'):
            continue
        huge_size = f[len('hugepages-'):]
        with open(_FREE_HUGEPAGES % (socket_id, f)) as p:
            huge_free = p.read()
        if huge_size == '2048kB':
            free_size += 2 * int(huge_free.rstrip())
        if huge_size == '1GB':
            free_size += 1024 * int(huge_free.rstrip())

    return free_size

def _node_for_lcore(lcore_id):
    """
    Get node of a cpu
    """
    node_number = -1
    for f in os.listdir(_NODE_OF_LCORE_ID % lcore_id):
        if not f.startswith('node'):
            continue
        node_number = int(f[len('node'):])
        break

    return node_number

def _eth_name(path):
    for f in os.listdir('%s' % path):
        return f

# --------------- public function to create a MachineDesc object ---------------

def scan_machine():
    machine = MachineDescription()

    machine.read_cpu_info()
    machine.read_pci_info()

    return machine
