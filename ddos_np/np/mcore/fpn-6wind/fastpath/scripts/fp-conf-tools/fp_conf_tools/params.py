# Copyright 2014, 6WIND S.A.

from __future__ import division
import math

from fp_conf_tools import util


# --------------------------- globals and define -------------------------------
# Any PMD allocate memory in Hugepage for RX and TX operation
# Memory needs is PMD dependent. Set value to the biggest need (ixgbe)
PMD_DMA_RING_ZONE = 65536

# TODO: MBUF_SIZE is architecture dependent.
# Used default value matching any architecture
MBUF_SIZE = 2624

# DPDK define
DPDK_MEMPOOL_HEADER = 1600000
DPDK_MEMPOOL_LOG = 512 * 2048 # 2048 elements of 512 size

# --------------------------- main class ---------------------------------------

class FastPathConfig(object):
    """
    This class manages the fast-path.env file
    """

    def __init__(self, addonlibrary, eal_options, fpnsdk_options, fp_options, nbtxd, nbrxd):
        self.fpmask = 0
        self.coremask = ''
        self.whitelist = []
        self.blacklist = []
        self.addonlibrary = addonlibrary
        self.hugepage = []
        self.ignore_netdev = []
        self.rxqshared = 0
        self.txqshared = 0
        self.memory = -1
        self.min_memory = 0
        self.mbuf = 16384
        self.min_mbuf = 0
        self.nbtxd = nbtxd
        self.nbrxd = nbrxd
        self.memchannel = -1
        self.cryptooption = {}
        self.cryptooption_count = 0
        self.specific_cryptooption = []
        self.additional_eal_options = eal_options
        self.additional_fpnsdk_options = fpnsdk_options
        self.additional_fp_options = fp_options
        self.hugepage_dir = ''

    def __str__(self):
        """
        Convert structure representation to the fast-path.env format
        """

        fpparm_txt = 'FP_MASK=0x%08x\n' % self.fpmask
        fpparm_txt += 'CORE_PORT_MAPPING="%s"\n' % self.coremask
        fpparm_txt += 'EAL_OPTIONS="'
        for eal in self.additional_eal_options:
            fpparm_txt += '%s ' % eal
        for wpci in self.whitelist:
            fpparm_txt += '-w %s ' % wpci
        for addon in self.addonlibrary:
            fpparm_txt += '-d %s ' % addon
        fpparm_txt += '"\n'
        fpparm_txt += 'FPNSDK_OPTIONS="--nb-mbuf=%d' % self.mbuf
        if self.rxqshared != 0:
            fpparm_txt += ' --rxq-shared=0x%08x' % self.rxqshared
        if self.txqshared != 0:
            fpparm_txt += ' --txq-shared=0x%08x' % self.txqshared
        if self.nbtxd != -1:
            fpparm_txt += ' --nb-txd=%d' % self.nbtxd
        if self.nbrxd != -1:
            fpparm_txt += ' --nb-rxd=%d' % self.nbrxd
        if len(self.additional_fpnsdk_options):
            for fpnsdk in self.additional_fpnsdk_options:
                fpparm_txt += ' %s' % fpnsdk
        for crypto_opt in self.cryptooption.itervalues():
            fpparm_txt += str(crypto_opt)
        fpparm_txt += '"\n'

        if len(self.additional_fp_options):
            fpparm_txt += 'FP_OPTIONS="'
            for fp in self.additional_fp_options:
                fpparm_txt += '%s ' % fp
            fpparm_txt += '"\n'
        fpparm_txt += 'NB_MEM_CHANNELS=%d\n' % self.memchannel
        fpparm_txt += 'FP_MEMORY=%d\n' % self.memory
        if self.hugepage_dir:
            fpparm_txt += 'HUGEPAGES_DIR=%s\n' % self.hugepage_dir
        fpparm_txt += 'NB_HUGEPAGES=%d' % self.hugepage[0]
        for i in range(1, len(self.hugepage)):
            fpparm_txt += ',%d' % self.hugepage[i]
        return fpparm_txt

    def _compute_hugepage(self, fp_mac, memory_need, nb_mbuf, fp_cpu_nb):
        """
        Compute hugepage

        :arg MachineDescription fp_mac:
            information about the machine and selected information
        :arg int memory_need:
            estimation of memory need
        :arg int nb_mbuf:
            number of allocated mbuf
        :arg int fp_cpu_nb:
            Number of cpu used by fast path
        :returns:
            Additional memory to add to the estimate memory need
        """
        additional_memory = 0
        for socket in fp_mac.cpu_info.sockets.itervalues():
            available_hugepage = socket.freehugepage
            used_cpu_per_numa = 0
            for core in socket.cores.itervalues():
                for htread in core.hyperthreads.itervalues():
                    if htread.state != 0:
                        used_cpu_per_numa += 1
            if fp_cpu_nb != 0:
                used_memory = math.ceil(memory_need * used_cpu_per_numa / fp_cpu_nb)
                mbuf_need = math.ceil(nb_mbuf * 2624 * used_cpu_per_numa / (fp_cpu_nb * 1048576))
                # Hugepage are not necessary contiguous. To avoid issue with mbuf
                # allocation per socket the needed size for mbuf must be less
                # than 50% of reserved hugepages
                # If it is not the case add some hugepages
                if (2 * mbuf_need) > used_memory:
                    additional_memory += 2 * mbuf_need - used_memory
                    used_memory = 2 * mbuf_need
                needed_hugepage = math.ceil(used_memory / 2)
            else:
                needed_hugepage = 0
            if available_hugepage >= needed_hugepage:
                self.hugepage.append(0)
            else:
                self.hugepage.append(needed_hugepage)
        return additional_memory

    def compute_from_pcilist(self, m, port_offset):
        """
        Compute first set of parameters:
           - fp_mask,
           - core_port_mapping,
           - dpdk add on library,
           - pci white list
           - memory channels

        :arg MachineDescription m:
            information about the machine and selected information
        :arg int port_offset:
            Value of port to set to the first physical network (the first
            are the virtual ons)
        :returns:
            Number of cpu used by fastpath (needed to compute other parameters)
        """

        cpu_list = []
        pmd_list = []
        wpci_list = []
        core_mapping = ''
        fp_mask = 0

        port_count = port_offset
        for i in range(0, m.pci_network_count):
            new_pmd_list = m.pci_network[i].info.card.required_addons
            for j in range(0, len(new_pmd_list)):
                if new_pmd_list[j] not in pmd_list:
                    pmd_list.append(new_pmd_list[j])
            if m.pci_network[i].info.status:
                wpci_list.append(m.pci_network[i].bus)
                for j in range(0, len(m.pci_network[i].info.used_cpu)):
                    new_coremap = 'c%d=' % m.pci_network[i].info.used_cpu[j]
                    if core_mapping.find(new_coremap) != -1:
                        core_mapping = core_mapping.replace(new_coremap,
                                                            '%s%d:' % (new_coremap,
                                                                       port_count))
                    else:
                        core_mapping += '/%s%d' % (new_coremap, port_count)
                    if m.pci_network[i].info.used_cpu[j] not in cpu_list:
                        cpu_list.append(m.pci_network[i].info.used_cpu[j])
                        fp_mask |= 2 ** m.pci_network[i].info.used_cpu[j]
                port_count += 1

        core_mapping.lstrip()
        for pmd in pmd_list:
            if not pmd in self.addonlibrary:
                self.addonlibrary.append(pmd)

        for crypto in m.pci_crypto.itervalues():
            if crypto.info.status == 1:
                cryptopmd = crypto.info.card.required_addons
                for newpmd in cryptopmd:
                    if not newpmd in self.addonlibrary:
                        self.addonlibrary.append(newpmd)

        for j in range(0, len(wpci_list)):
            self.whitelist.append(wpci_list[j])

        if m.cpu_info.mem_channel != -1:
            self.memchannel = m.cpu_info.mem_channel
        else:
            self.memchannel = 3
        self.fpmask = fp_mask
        self.coremask = core_mapping[1:]

        return len(cpu_list)

    def compute_memory_info(self, m, fp_conf, fp_cpu_nb):
        """
        Compute second set of parameters:
           - fp_memory and hugepage,
           - rxq-shared and txq-shared,
           - mbuf

        :arg MachineDescription m:
            information about the machine and selected information
        :arg FastPathCompilationOption fp_conf:
            information about compilation option mandatory to compute memory needs
        :arg int fp_cpu_nb:
            Number of cpu used by fast path
        """
        nb_mbuf = 0
        port_count = 0
        txq_mask = 0
        rxq_mask = 0
        memory_need = 0

        if m.nb_txd != -1:
            nb_txd = m.nb_txd
        else:
            nb_txd = 512

        if m.nb_rxd != -1:
            nb_rxd = m.nb_rxd
        else:
            nb_rxd = 128

        # for emulex card the RX ring is always 1024
        if 'librte_pmd_oce.so' in self.addonlibrary:
            nb_rxd = 1024

        # TODO: parse virtual interface
        for i in range(0, m.pci_network_count):
            if m.pci_network[i].info.status:
                if ((m.pci_network[i].info.max_txq != -1) and
                        (m.pci_network[i].info.max_txq <
                         fp_cpu_nb)):
                    txq_mask |= 2 ** port_count
                    nb_mbuf += nb_txd
                    memory_need += PMD_DMA_RING_ZONE
                else:
                    nb_mbuf += nb_txd
                    memory_need += PMD_DMA_RING_ZONE * fp_cpu_nb
                if ((m.pci_network[i].info.max_rxq != -1) and
                        (m.pci_network[i].info.max_rxq <
                         len(m.pci_network[i].info.used_cpu))):
                    rxq_mask |= 2 ** port_count
                    nb_mbuf += nb_rxd
                    memory_need += PMD_DMA_RING_ZONE
                else:
                    nb_mbuf += len(m.pci_network[i].info.used_cpu) * nb_rxd
                    memory_need += len(m.pci_network[i].info.used_cpu) * PMD_DMA_RING_ZONE
                port_count += 1

        # Compute needed mbuf
        nb_mbuf += fp_cpu_nb * (m.cpu_info.thread_count - fp_cpu_nb) * fp_conf.ring_size

        #print "nb_mbuf before round up: %d" %nb_mbuf
        self.min_mbuf = nb_mbuf
        nb_mbuf = math.ceil(nb_mbuf / 32768) * 32768
        #nb_mbuf = util.round_up(nb_mbuf, 32768)

        # RTE mempool for mbuf and log
        memory_need += (nb_mbuf * MBUF_SIZE) + DPDK_MEMPOOL_LOG
        memory_need += util.round_square2(nb_mbuf + 1) * 8

        # Add mempool header for mbuf and log
        memory_need += DPDK_MEMPOOL_HEADER * (m.cpu_info.socket_count + 1)

        used_socket = 0
        # Add heap need for socket used by dpdk
        for socket in m.cpu_info.sockets.itervalues():
            if socket.used_cores:
                used_socket += 1

        # crypto need
        memory_need += fp_conf.memory_need(used_socket)

        # Set memory need in Mb
        memory_need = math.ceil(memory_need / 1048576)

        # Add heap need for vnb and socket used by dpdk
        memory_need += util.get_minimal_heap_size(util.HEAP_SIZE_IN_MB) * (used_socket + 1)

        self.min_memory = memory_need

        # Last allocation is a 11Mb heap for VNB.
        # With multisocket architecture add 11Mb we must ensure that a 11Mb free
        # zone is present on one socket, so add an additional 11Mb needs
        if m.cpu_info.socket_count > 1:
            memory_need += util.get_minimal_heap_size(util.HEAP_SIZE_IN_MB)

        # Add 5% marging for memory fragmentation
        memory_need = memory_need + math.ceil(memory_need / 20)

        # compute NR_HUGEPAGE
        additional_memory = self._compute_hugepage(m, memory_need,
                                                   nb_mbuf, fp_cpu_nb)

        self.rxqshared = rxq_mask
        self.txqshared = txq_mask
        self.memory = memory_need + additional_memory
        self.mbuf = nb_mbuf

    def compute_crypto_info(self, crypto, fp_mac):
        """
        Compute crypto options (-T) for the given crypto structure

        :arg MachineDescription fp_mac:
            information about the machine and selected information
        :arg PCIGeneric crypto:
            information about the crypto PCI card
        """
        name = crypto.info.card.capabilities.option_name
        mode = crypto.info.card.capabilities.option_mode
        if mode == 0:
            return
        crypto_opt = CryptoMask(name)
        self.cryptooption[self.cryptooption_count] = crypto_opt
        self.cryptooption_count += 1
        for socket_id, socket in fp_mac.cpu_info.sockets.iteritems():
            crypto_dev_list = []
            if crypto.numa_node == socket_id:
                crypto_dev_list.append(0)
                self.whitelist.append(crypto.bus)
            count = 1
            for i in crypto.info.link_key:
                if fp_mac.pci_crypto[i].numa_node == socket_id:
                    crypto_dev_list.append(count)
                    self.whitelist.append(fp_mac.pci_crypto[i].bus)
                count += 1
            dev_count = len(crypto_dev_list)
            count = 0
            sub_count = 0
            for core_id in socket.used_cores:
                for htread_id, htread in socket.cores[core_id].hyperthreads.iteritems():
                    if htread.state:
                        if mode == 1:
                            crypto_opt.cryptomask += '/c%d=%d' % (htread_id,
                                                                  crypto_dev_list[count])
                            count += 1
                        else:
                            if sub_count == 0:
                                crypto_opt.cryptomask += '/c%d=%d.0.0' % (htread_id,
                                                                          crypto_dev_list[count])
                            elif sub_count == 1:
                                crypto_opt.cryptomask += '/c%d=%d.0.1' % (htread_id,
                                                                          crypto_dev_list[count])
                            elif sub_count == 2:
                                crypto_opt.cryptomask += '/c%d=%d.1.0' % (htread_id,
                                                                          crypto_dev_list[count])
                            elif sub_count == 3:
                                crypto_opt.cryptomask += '/c%d=%d.1.1' % (htread_id,
                                                                          crypto_dev_list[count])
                            sub_count += 1
                            if sub_count == 4:
                                count += 1
                                sub_count = 0
                        if count == dev_count:
                            count = 0

    def read_eal_options(self, fp_file):
        eal_options = util.read_param_value_in_file(fp_file, 'EAL_OPTIONS', ' ')
        next_op = 0
        for eal in eal_options:
            if next_op:
                if next_op == 1:
                    self.addonlibrary.append(eal)
                if next_op == 2:
                    self.whitelist.append(eal)
                if next_op == 3:
                    self.blacklist.append(eal)
                next_op = 0
            else:
                if eal.startswith('-d'):
                    if len(eal) > 2:
                        self.addonlibrary.append(eal[2:])
                    else:
                        next_op = 1
                elif eal.startswith('-w'):
                    if len(eal) > 2:
                        self.whitelist.append(eal[2:])
                    else:
                        next_op = 2
                elif eal.startswith('-b'):
                    if len(eal) > 2:
                        self.blacklist.append(eal[2:])
                    else:
                        next_op = 3
                else:
                    self.additional_eal_options.append(eal)

    def read_fpnsdk_options(self, fp_file):
        fpnsdk_options = util.read_param_value_in_file(fp_file,
                                                       'FPNSDK_OPTIONS', ' ')
        next_op = 0
        for fpnsdk in fpnsdk_options:
            if next_op:
                if next_op == 1:
                    self.specific_cryptooption.append(fpnsdk)
                next_op = 0
            else:
                if fpnsdk.startswith('-T'):
                    next_op = 1
                elif fpnsdk.startswith('--nb-mbuf='):
                    self.mbuf = int(fpnsdk[10:])
                elif fpnsdk.startswith('--nb-rxd='):
                    self.nbrxd = int(fpnsdk[9:])
                elif fpnsdk.startswith('--nb-txd='):
                    self.nbtxd = int(fpnsdk[9:])
                elif fpnsdk.startswith('--rxq-shared=0x'):
                    self.rxqshared = int(fpnsdk[15:], 16)
                elif fpnsdk.startswith('--txq-shared=0x'):
                    self.txqshared = int(fpnsdk[15:], 16)
                else:
                    self.additional_fpnsdk_options.append(fpnsdk)

# --------------------------- subclasses ---------------------------------------

class CryptoMask(object):
    """
    This subclass manages crypto options (-T) of the fast-path.env file
    """
    def __init__(self, name):
        self.name = name
        self.cryptomask = ''

    def __str__(self):
        """
        Convert crypto structure representation to the -T format
        """
        cryptomask_txt = ' -T %s:%s' %(self.name, self.cryptomask[1:])
        return cryptomask_txt

# --------------- public functions to create a FastPathConfig object --------

def generate_parameter(m_desc, fp_conf):
    """
    Generate the structure representation of a fast-path.env file with
    information provided by end-user
    """
    fpparam = FastPathConfig(m_desc.addon_options, m_desc.eal_options,
                                m_desc.fpnsdk_options, m_desc.fp_options,
                                m_desc.nb_txd, m_desc.nb_rxd)
    # TODO parse virtual interface (the nth first port)
    cpu_count = fpparam.compute_from_pcilist(m_desc, 0)
    fpparam.compute_memory_info(m_desc, fp_conf, cpu_count)
    for crypto in m_desc.pci_crypto.itervalues():
        if crypto.info.status == 1:
            fpparam.compute_crypto_info(crypto, m_desc)

    return fpparam

def read_config(fp_file):
    """
    Convert a fast-path.env file to a structure representation
    """

    fpparam = FastPathConfig([], [], [], [], -1, -1)
    fp_mask = util.read_param_value_in_file(fp_file, 'FP_MASK', 'x')
    if len(fp_mask) == 2:
        fpparam.fpmask = int(fp_mask[1], 16)

    core_mapping = util.read_param_value_in_file(fp_file, 'CORE_PORT_MAPPING')
    fpparam.coremask = core_mapping

    fp_memory = util.read_param_value_in_file(fp_file, 'FP_MEMORY')
    if fp_memory:
        fpparam.memory = int(fp_memory)

    mem_channel = util.read_param_value_in_file(fp_file, 'NB_MEM_CHANNELS')
    if mem_channel:
        fpparam.memchannel = int(mem_channel)

    nb_hugepages = util.read_param_value_in_file(fp_file, 'NB_HUGEPAGES', ',')
    if nb_hugepages:
        for huge in nb_hugepages:
            fpparam.hugepage.append(int(huge))

    hugepages_dir = util.read_param_value_in_file(fp_file, 'HUGEPAGES_DIR')
    if hugepages_dir:
        fpparam.hugepage_dir = hugepages_dir

    ignore_netdev = util.read_param_value_in_file(fp_file, 'IGNORE_NETDEV', ' ')
    if ignore_netdev:
        for net in ignore_netdev:
            fpparam.ignore_netdev.append(net)

    fpparam.read_eal_options(fp_file)

    fpparam.read_fpnsdk_options(fp_file)

    fpparam.additional_fp_options = util.read_param_value_in_file(fp_file,
                                                                  'FP_OPTIONS',
                                                                  ' ')

    return fpparam

# --------------- other public functions  --------------------------------------

def check_config(current_conf, needed_conf, previous_errors):  # pylint: disable=R0912
    """
    Compare an existing configuration with a minimal configuration.
    Displays error and warning
    """
    has_errors_or_warnings = False
    if previous_errors:
        print previous_errors
        has_errors_or_warnings = True

    if current_conf.whitelist and (current_conf.blacklist or current_conf.ignore_netdev):
        print 'ERROR: Invalid configuration: used whitelist and blacklist together'
        has_errors_or_warnings = True

    if current_conf.fpmask != needed_conf.fpmask:
        common_fpmask = util.mask_comp(current_conf.fpmask, needed_conf.fpmask)
        if common_fpmask[0] != 0:
            print 'Warning: The following cores %r are used by fastpath but do not listen any ports' % util.mask_to_list(common_fpmask[0])
        if common_fpmask[1] != 0:
            print 'ERROR: The following cores %r are not used by fastpath but listen some ports' % util.mask_to_list(common_fpmask[1])
        print '       Recommended value for FP_MASK is 0x%08x' % needed_conf.fpmask
        has_errors_or_warnings = True

    if current_conf.mbuf < needed_conf.min_mbuf:
        print 'ERROR: Not enough mbuf. Recommended value is %d' % needed_conf.mbuf
        has_errors_or_warnings = True

    if current_conf.rxqshared != needed_conf.rxqshared:
        common_rxqshared = util.mask_comp(current_conf.rxqshared, needed_conf.rxqshared)
        if common_rxqshared[0] != 0:
            print 'Warning: The following ports %r are RX shared whereas it is not needed' % util.mask_to_list(common_rxqshared[0])
        if common_rxqshared[1] != 0:
            print 'ERROR: The following ports %r must be RX shared' % util.mask_to_list(common_rxqshared[1])
        print '       Recommended value for --rxq-shared is 0x%08x' % needed_conf.rxqshared
        has_errors_or_warnings = True

    if current_conf.txqshared != needed_conf.txqshared:
        common_txqshared = util.mask_comp(current_conf.txqshared, needed_conf.txqshared)
        if common_txqshared[0] != 0:
            print 'Warning: The following ports %r are TX shared whereas it is not needed' % util.mask_to_list(common_txqshared[0])
        if common_txqshared[1] != 0:
            print 'ERROR: The following ports %r must be TX shared' % util.mask_to_list(common_txqshared[1])
        print '       Recommended value for --txq-shared is 0x%08x' % needed_conf.txqshared
        has_errors_or_warnings = True

    for addon in needed_conf.addonlibrary:
        if not addon in current_conf.addonlibrary:
            print 'ERROR: The following EAL add-on %r must be added' % addon
            has_errors_or_warnings = True

    if (current_conf.memory != -1) and (current_conf.memory < needed_conf.memory):
        if current_conf.memory >= needed_conf.min_memory:
            print 'Warning: Provided FP_MEMORY can be not sufficient due to huge page fragmentation'
        else:
            print 'ERROR: Provided FP_MEMORY is not sufficient'
        print '       Recommended value for FP_MEMORY is %d (minimal value is %d)' % (needed_conf.memory, needed_conf.min_memory)
        has_errors_or_warnings = True

    for i in range(0, len(needed_conf.hugepage)):
        if needed_conf.hugepage[i] != 0:
            if len(current_conf.hugepage) < i:
                print 'ERROR: Provided NB_HUGEPAGES is not sufficient'
                print '       Recommended value for NB_HUGEPAGES is ' + str(needed_conf.hugepage)
                has_errors_or_warnings = True
                break
            else:
                if current_conf.hugepage[i] < needed_conf.hugepage[i]:
                    print 'ERROR: Provided NB_HUGEPAGES is not sufficient'
                    print '       Recommended value for NB_HUGEPAGES is ' + str(needed_conf.hugepage)
                    has_errors_or_warnings = True
                    break

    if not has_errors_or_warnings:
        print 'No errors or warnings'
