# Copyright 2014, 6WIND S.A.

from __future__ import division
from distutils.spawn import find_executable  # pylint: disable=E0611,F0401
import math
import os
import re
import sys

from fp_conf_tools import util


# --------------------------- globals and define -------------------------------
#TODO: modify makefile to set elt_size, size, max_core, cacheline_size,
#      max_port in a config file

_FPN_MEMORY_POOL = {
    'generic_crypto_session': {
        'key': 'CONFIG_MCORE_FPN_CRYPTO_GENERIC',
        'size': 'session_nb',
        'elt_size': 2752
    },
    'generic_crypto_buffer': {
        'key': 'CONFIG_MCORE_FPN_CRYPTO_GENERIC',
        'size': 'buffers_nb',
        'elt_size': 704
    }
}

_FP_MEMORY_POOL = {
    'socket': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_SOCKET_POOL_SIZE',
        'rule': 1,
        'elt_size': 592
    },
    'inpcbpl': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_INPCB_POOL_SIZE',
        'rule': 1,
        'elt_size': 216
    },
    'in6pcbpl': {
        'key': 'CONFIG_MCORE_SOCKET_INET6',
        'size': 'CONFIG_MCORE_IN6PCB_POOL_SIZE',
        'rule': 1,
        'elt_size': 256
    },
    'tcpcbpl': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_TCPCB_POOL_SIZE',
        'rule': 1,
        'elt_size': 616
    },
    'sackholepl': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_TCP_SACKHOLE_POOL_SIZE',
        'rule': 1,
        'elt_size': 96
    },
    'tcpipqepl': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_TCPIPQE_POOL_SIZE',
        'rule': 1,
        'elt_size': 136
    },
    'synpl': {
        'key': 'CONFIG_MCORE_SOCKET',
        'size': 'CONFIG_MCORE_TCP_SYNCACHE_POOL_SIZE',
        'rule': 1,
        'elt_size': 288
    },
    'tg_tcp_flows': {
        'key': 'CONFIG_MCORE_TRAFFIC_GEN',
        'size': 262144,
        'rule': 0,
        'elt_size': 40
    },
    'uso': {
        'key': 'CONFIG_MCORE_FPU_SO',
        'size': 65535,
        'rule': 0,
        'elt_size': 24
    }
}

_REL_FPNSDK_CFG = '../6WINDGate/etc/fpnsdk.config'
_REL_FP_CFG = '../6WINDGate/etc/fp.config'

# --------------------------- main class ---------------------------------------

class FastPathCompilationOption(object):

    def __init__(self):
        self.max_core = 1
        self.max_port = 1
        self.cacheline_size = 1
        self.ring_size = 1
        self.crypto_session_nb = 0
        self.crypto_buffers_nb = 0
        self.mempool_list = {}

    def __str__(self):
        fpconf_txt = 'max_core: %d, max_port: %d\n' % (self.max_core,
                                                       self.max_port)
        for key, value in self.mempool_list.iteritems():
            fpconf_txt += 'name %s, ' % key
            fpconf_txt += str(value)
        return fpconf_txt

    def fpnsdk_ports_cores_rings(self, buf):
        """
        Get port, core and cacheline information

        :arg str buf:
            Content of the fpnsdk.config that contains information for port
            core and cacheline
        """
        if 'CONFIG_MCORE_FPE_VFP=' in buf:
            self.max_core = 128
            self.max_port = 64
            self.cacheline_size = 32
        elif 'CONFIG_MCORE_ARCH_OCTEON=' in buf:
            self.max_core = 32
            self.max_port = 63
            self.cacheline_size = 128
        elif 'CONFIG_MCORE_ARCH_DPDK=' in buf:
            self.max_core = 128
            self.max_port = 32
            self.cacheline_size = 64
        elif 'CONFIG_MCORE_ARCH_XLP=' in buf:
            self.max_core = 64
            self.max_port = 128
            self.cacheline_size = 64
        elif 'CONFIG_MCORE_ARCH_TILEGX=' in buf:
            self.max_core = 72
            self.max_port = 32
            self.cacheline_size = 64

    def memory_need(self, count):
        """
        Compute memory size needed by the different memory pool

        :arg int count:
            Number of used sockets (some memory pool are present
            on each sockets)
        """
        need = 0
        for value in self.mempool_list.itervalues():
            if value.usedcount:
                mul = count
            else:
                mul = 1
            if value.cachealigned:
                new_need = math.ceil(value.elt_size / self.cacheline_size)
                new_need *= value.elt_nb * mul * self.cacheline_size
            else:
                new_need = value.elt_nb * value.elt_size * mul
            # Add ring needs
            new_need += util.round_square2(value.elt_nb) * 8 * mul
            # Add fpn_mempool header
            new_need += 100000 * mul
            # Set to minimal allocation if needed
            if new_need < (util.get_minimal_heap_size(1) * mul):
                new_need = util.get_minimal_heap_size(1) * mul
            need += new_need
        return need

    def add_memory(self, name, cachealigned, elt_nb, elt_size, count):
        """
        Add a memory pool

        :arg string name:
            Name of the memory pool
        :arg boolean cachealigned:
            True if the elt_size must be aligned to the cache size
        :arg int elt_nb:
            Number of elements
        :arg int elt_size:
            Size of an element
        :arg boolean count:
            True if the memory pool can be created several times (on by used
            socket)
        """
        if not name in self.mempool_list:
            self.mempool_list[name] = MemoryPool(cachealigned, elt_nb,
                                                 elt_size, count)

    def remove_memory(self, name):
        """
        Remove a memory pool

        :arg string name:
            Name of the memory pool
        :arg int count:
            Number of used sockets (some memory pool are present
            on each sockets)
        """
        if name in self.mempool_list:
            del self.mempool_list[name]

# --------------------------- subclasses ---------------------------------------

class MemoryPool(object):
    def __init__(self, cachealigned, elt_nb, elt_size, used_count):
        self.cachealigned = cachealigned
        self.elt_nb = elt_nb
        self.elt_size = elt_size
        self.usedcount = used_count

    def __str__(self):
        mempool_txt = 'elt_nb: %d, elt_size: %d\n' % (self.elt_nb,
                                                      self.elt_size)
        return mempool_txt

# --------------------------- private functions --------------------------------

def _config_isset(key, buf):
    """
    Check is the key is set to y in the provided buffer

    :arg string key:
        key to find
    :arg string file:
        file to parse
    :returns:
        True if key is present
    """
    return _config_value(key, buf) == 'y'

def _config_value(key, buf):
    """
    Find value set to key in the provided file

    :arg string key:
        key to find
    :arg string file:
        file to parse
    :returns:
        value set to the key or None if key is not present
    """
    match = re.search(r'^%s=(.*)$' % key, buf, re.MULTILINE)
    if match:
        return match.group(1)
    else:
        return None

# ------- public function to create a FastPathCompilationOption object ---------

def parse_fp_options():
    """
    Parse configuration file to retrieve main information mandatory to compute
    memory needs of fast path regarding the fast-path.anv file configuration
    """

    # Retrieve path where important config files are installed
    fpcpopt = FastPathCompilationOption()
    fp_executable = find_executable('fast-path.sh')
    if not fp_executable:
        print 'ERROR: fast path is not installed on the machine'
        sys.exit(1)
    path = os.path.dirname(fp_executable)

    with open(os.path.join(path, _REL_FPNSDK_CFG), 'r') as f:
        buf = f.read()

        fpcpopt.fpnsdk_ports_cores_rings(buf)

        crypto_session_nb = int(_config_value('CONFIG_MCORE_CRYPTO_MAX_SESSIONS', buf))
        fpcpopt.crypto_session_nb = crypto_session_nb
        crypto_buffers_nb = int(_config_value('CONFIG_MCORE_CRYPTO_BUFFERS', buf))
        fpcpopt.crypto_buffers_nb = crypto_buffers_nb
        ring_offset = int(_config_value('CONFIG_MCORE_FPN_DRING_ORDER', buf))
        fpcpopt.ring_size = 2 ** ring_offset

        for key, value in _FPN_MEMORY_POOL.iteritems():
            if _config_isset(value['key'], buf):
                if value['size'] == 'session_nb':
                    fpcpopt.mempool_list[key] = MemoryPool(True,
                                                           fpcpopt.crypto_session_nb,
                                                           value['elt_size'],
                                                           False)
                else:
                    fpcpopt.mempool_list[key] = MemoryPool(True,
                                                           fpcpopt.crypto_buffers_nb,
                                                           value['elt_size'],
                                                           False)

    with open(os.path.join(path, _REL_FP_CFG), 'r') as f:
        buf = f.read()

        for key, value in _FP_MEMORY_POOL.iteritems():
            if _config_isset(value['key'], buf):
                if value['size'].isdigit():
                    size = value['size']
                else:
                    size = int(_config_value(value['size'], buf))
                if value['rule'] == 1:
                    size += 32 * fpcpopt.max_core
                fpcpopt.mempool_list[key] = MemoryPool(True, size,
                                                       value['elt_size'], False)

    return fpcpopt
