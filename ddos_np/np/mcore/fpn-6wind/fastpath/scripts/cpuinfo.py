#!/usr/bin/env python

import re

#------------------------------------------------------------------------------
class CPU:

    def __init__(self, model_name):
        self.model_name = model_name
        self.sockets = {}
        self.socket_count = 0
        self.core_count = 0
        self.thread_count = 0

    def __str__(self):
        sockets = sorted(list(self.sockets.values()), key=lambda s: s.socket_id)
        sockets_lines = []
        for s in sockets:
            sockets_lines.append(str(s).splitlines())

        cpu_txt = ''
        for i in range(len(sockets_lines[0])):
            for s in sockets_lines:
                cpu_txt += '  ' + s[i]
            cpu_txt += '\n'

        return cpu_txt.rstrip()

class Socket:

    def __init__(self, socket_id):
        self.socket_id = socket_id
        self.cores = {}

    def __str__(self):
        core_ids = sorted(self.cores.keys())

        socket_txt = ''

        while core_ids:
            core1 = core_ids.pop(0)
            core2 = core_ids.pop(0)

            lines1 = str(self.cores[core1]).splitlines()
            lines2 = str(self.cores[core2]).splitlines()

            for i in range(len(lines1)):
                line = '| %s %s |' % (lines1[i], lines2[i])
                socket_txt += line + '\n'

        header = ('{:^%d}' % len(line)).format('socket %d' % self.socket_id)
        line = '+%s+\n' % ('-' * (len(line) - 2))
        return header + '\n' + line + socket_txt + line

class Core:

    def __init__(self, core_id):
        self.core_id = core_id
        self.hyperthreads = []

    def __str__(self):
        if self.core_id > 1000:
            return '         \n' * 4
        else:
            threads_txt = ''
            for t in sorted(self.hyperthreads):
                threads_txt += '|%3d' % t
            threads_txt += '|'
            line = '+%s+\n' % ('-' * (len(threads_txt) - 2))
            header = ('{:>%d}' % len(threads_txt)).format('c%d' % self.core_id)
            return header + '\n' + line + threads_txt + '\n' + line

#------------------------------------------------------------------------------
CPUINFO_RE = re.compile(r'processor\s+:\s+(\d+).*?' +
                        r'model name\s+:\s+(.*?)stepping.*?' +
                        r'physical id\s+:\s+(\d+).*?' +
                        r'core id\s+:\s+(\d+)', re.DOTALL)
def parse_cpuinfo(cpuinfo):

    cpu = CPU(model_name='Unknown')

    for match in CPUINFO_RE.finditer(cpuinfo):
        cpu.model_name = match.group(2)

        socket_id = int(match.group(3))
        core_id = int(match.group(4))
        hyperthread_id = int(match.group(1))

        if not socket_id in cpu.sockets:
            cpu.sockets[socket_id] = Socket(socket_id)
            cpu.socket_count += 1
        socket = cpu.sockets[socket_id]

        if not core_id in socket.cores:
            socket.cores[core_id] = Core(core_id)
            cpu.core_count += 1
        core = socket.cores[core_id]

        core.hyperthreads.append(hyperthread_id)
        cpu.thread_count += 1

    for s in list(cpu.sockets.values()):
        if len(s.cores) % 2 != 0:
            # nasty hack to make it work with sockets that have and uneven
            # number of cores
            c = Core(9999999)
            s.cores[9999999] = c

    return cpu

#------------------------------------------------------------------------------
def print_cpu_layout(cpu):
    print('Processor: "%s"' % cpu.model_name.strip())
    print('')
    print('\tSockets: %s, Cores: %s, HyperThreads: %s' % (cpu.socket_count,
                                                     cpu.core_count,
                                                     cpu.thread_count))
    print('')
    print(cpu)

#------------------------------------------------------------------------------
if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Parse the output of /proc/cpuinfo')

    parser.add_argument('cpu_info',
                        metavar='FILE',
                        help='A file containing the output of /proc/cpuinfo. '
                             'If this argument is ommitted, standard input is read.',
                        type=argparse.FileType('r'),
                        nargs='*')
    parser.add_argument('-m', '--core-mask',
                        dest='core_mask',
                        help='Print a mask of the specified cores. '
                             'Use -m "SOCKET:CORE,SOCKET:CORE,..."')

    args = parser.parse_args()

    if args.cpu_info:
        buf = args.cpu_info[0].read()
    else:
        buf = sys.stdin.read()

    cpu = parse_cpuinfo(buf)
    print_cpu_layout(cpu)

    if args.core_mask:
        threads = []
        for token in args.core_mask.split(','):
            socket_id, core_id = token.split(':')
            socket = cpu.sockets[int(socket_id)]
            core = socket.cores[int(core_id)]
            threads += list(core.threads.keys())

        mask = 0
        for t in threads:
            mask |= 2 ** t
        print('Threads:', ', '.join(map(str, sorted(threads))))
        print('Mask:', hex(mask), '(%s)' % bin(mask))

