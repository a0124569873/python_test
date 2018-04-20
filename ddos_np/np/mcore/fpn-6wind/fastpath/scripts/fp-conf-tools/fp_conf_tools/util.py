# Copyright 2014, 6WIND S.A.

import os
import shlex
import subprocess


# --------------------------- globals and define -------------------------------
# On dpdk any created heap as a minimal size of 11 Mb
HEAP_SIZE_IN_MB = 0
HEAP_SIZE_IN_BYTES = 1
_DPDK_HEAP_SIZE = 11

# --------------------------- private functions --------------------------------

def _check_cpu_list(cpulist_string):
    """
    Check that given string matchs kernel representation using the PCI
    card (representation has the  'a-b,c-d,...' format).

    :arg str cpulist_string:
        string representation of cpus to check
    :returns:
        True if the string matchs, False otherwise
    """
    tmp = cpulist_string.rsplit(',')
    for i in range(0, len(tmp)):
        if tmp[i].isdigit() == False:
            tmp2 = tmp[i].rsplit('-')
            if len(tmp2) != 2:
                return False
            if (tmp2[0].isdigit() == False) or (tmp2[1].isdigit() == False):
                return False
            if int(tmp2[0]) >= int(tmp2[1]):
                return False
    return True

def _run_multi_command(cmd):
    """
    Execute multiple shell commands in one line

    :returns:
        The output of the commands
    """

    f = os.popen(cmd)
    buf = f.read()
    return buf

def _run_command(cmd, fail_on_error=False, **popenargs):
    """
    Execute a single shell command.

    :raises subprocess.CalledProcessError:
        If ``fail_on_error`` is ``True`` and the command exit status is not 0.
    :returns:
        The output of the command
    """
    process = subprocess.Popen(shlex.split(cmd),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               **popenargs)
    stdout, _ = process.communicate()
    retcode = process.wait()

    if fail_on_error and retcode != 0:
        raise subprocess.CalledProcessError(retcode, cmd, output=stdout)
    else:
        return stdout

# --------------- public functions  --------------------------------------------

def clear(mode):
    """
    Clear the console
    """
    if mode:
        #sys.stdout.write('\f')
        os.system("clear")
    else:
        print
        print

def round_square2(value):
    """
    Compute the first power of 2 greater or equal to value

    :returns:
        A power of 2
    """
    i = 1

    while value > i:
        i *= 2

    return i

def mask_to_list(mask):
    """
    Compute list of bit position set in a mask

    :returns:
        list of bit position set in the mask
    """
    i = 0
    bit_list = []
    while mask != 0:
        if mask & 1:
            bit_list.append(i)
        i += 1
        mask >>= 1

    return bit_list

def mask_comp(mask1, mask2):
    """
    Compare two bit masks

    :returns:
        A list of 2 bit masks where:
          - the first one is bits present in mask one but not in mask two
          - the second one is bits present in mask two but not in mask one
    """
    mask = []

    mask.append(mask1 - (mask1 & mask2))
    mask.append(mask2 - (mask1 & mask2))

    return mask

def get_cpu_list(cpulist_string, range_list):
    """
    Provides a list representation of the cpulist_string
    If a range_list is provided check that the cpulist is included in the
    provided range_list

    :arg str cpulist_string:
        string representation of cpus in the kernel format: a-b,c-d
    :arg str range_list:
        string representation of authorized cpus in the kernel format: a-b,c-d
    :returns:
        List representation of the cplulist_string.
        The list is empty if:
            cpulist has a wrong format
            cpulist is not included in the range_list (if provided)
    """
    tmp_list = []

    if _check_cpu_list(cpulist_string) == False:
        return tmp_list

    tmp = cpulist_string.rsplit(",")
    for i in range(0, len(tmp)):
        if tmp[i].isdigit() == False:
            tmp2 = tmp[i].rsplit("-")
            for j in range(int(tmp2[0]), int(tmp2[1]) + 1):
                tmp_list.append(j)
        else:
            tmp_list.append(int(tmp[i]))

    # sort the list and remove duplicate
    tmp2_list = sorted(set(tmp_list))

    # check if selection is included in the authorized cpu list (range_list)
    if range_list:
        if set(tmp2_list).issubset(set(range_list)) == False:
            return []

    return tmp2_list

def cpu_list_to_string(cpu_list):
    """
    Provides a string representation of a list of cpus

    :arg list cpu_list:
        list of cpus
    :returns:
        A string representation with the kernel format: a-b,c-d
    """
    if not cpu_list:
        return ''

    first = cpu_list[0]
    last_tested = first
    cpu_string = '%d' % first

    for i in range(1, len(cpu_list)):
        if cpu_list[i] > last_tested + 1:
            if last_tested == first:
                cpu_string += ',%d' % cpu_list[i]
            else:
                cpu_string += '-%d,%d' % (last_tested, cpu_list[i])
            first = cpu_list[i]
        last_tested = cpu_list[i]

    if last_tested != first:
        cpu_string += '-%d' % last_tested

    return cpu_string

def get_minimal_heap_size(mode):
    """
    Gives the minimal heap size allocated by DPDK

    :arg int mode:
        enum to indicates size units (HEAP_SIZE_IN_BYTES for bytes,
        HEAP_SIZE_IN_MB for Mb)
    """
    min_heap_size = _DPDK_HEAP_SIZE

    if mode == HEAP_SIZE_IN_BYTES:
        min_heap_size *= 1024*1024

    return min_heap_size

def read_param_value_in_file(fp_file, key, delimiter=None):
    """
    Parse the given fp_file to return value set to key.

    :arg str fp_file:
        The .env file to source.
    :arg str key:
        The name of the parameter to read
    :arg str delimiter:
        delimeter used to split the value set to key

    For example if fp_file contains INFO=a:b:c

    >>> read_param(fp_file, 'INFO')
    'a:b:c'
    >>> read_param(fp_file, 'INFO', ':')
    ['a', 'b', 'c']
    """
    result = _run_multi_command('. %s && echo $%s' % (fp_file, key))

    result = result.rstrip()
    if delimiter:
        if len(result):
            return result.rsplit(delimiter)
        else:
            return []
    else:
        return result

def lspci(option):
    """
    Execute a lspci command with the provided option

    :arg str option:
        Option of the lspci command

    """
    return _run_command('lspci %s' % option)

def find(path, name, only_folders=True):
    """
    Retrieve the path of a given folder or file name.

    :arg str path:
        The root folder to parse
    :arg str name:
        file or folder to find
    :arg boolean only_folders:
        Search folder only or file and folder

    Execute an aquivalent of find shell command :
      find path -name name
    """
    for root, dirs, files in os.walk(path):
        if only_folders:
            items = dirs
        else:
            items = dirs + files
        if name in items:
            return os.path.join(root, name)
    return None
