#!/usr/bin/env python

import argparse
import os
import sys

from fp_conf_tools import machine, util
from fp_conf_tools import params
from fp_conf_tools import memory


# --------------------------- globals and define -------------------------------

# --------------------------- menus -------------------------------------------
def _edit_cryptocard(fp_mac, fp_mem, clear_mode):
    """
    Choice of crypto cards
    """
    while True:
        util.clear(clear_mode)

        print 'Crypto card selection'
        print '=====================\n'
        print 'B - back\n'
        for key, pci in fp_mac.pci_crypto.iteritems():
            crypto = pci.get_crypto()
            if crypto.can_be_selected():
                name = crypto.get_crypto_name()
                if crypto.is_selected():
                    print '%d - %s is selected' % (key, name)
                else:
                    print '%d - %s is not selected' % (key, name)

        ans = raw_input('Enter selection to toggle it: ')
        if (ans == 'b') or (ans == 'B') or (ans == ''):
            break
        if ans.isdigit():
            if int(ans) in fp_mac.pci_crypto:
                selected_crypto = fp_mac.pci_crypto[int(ans)].get_crypto()
                if selected_crypto.can_be_selected():
                    selected_crypto.toggle_info(fp_mem, fp_mac.addon_options)
                else:
                    raw_input('Invalid selection. Press enter to continue')
            else:
                raw_input('Invalid selection. Press enter to continue')
        else:
            raw_input('Invalid selection. Press enter to continue')


def _edit_ethcard(fp_mac, pci_nb, clear_mode):

    available_cpu = fp_mac.available_cpu(pci_nb)
    name = fp_mac.get_network_name(pci_nb)
    eth = fp_mac.get_network_eth(pci_nb)
    if eth == 'none':
        text_info = 'Configure %s PCI card (not mounted on any eth)' % name
    else:
        text_info = 'Configure %s PCI card mounted on %s' % (name, eth)

    while True:
        util.clear(clear_mode)
        print text_info
        print '=' * len(text_info)
        print


        if fp_mac.get_network_state(pci_nb) == 0:
            print('Card is not selected. Available cpu to manage this card are %s'
                  % util.cpu_list_to_string(available_cpu))
        else:
            print('Card is selected with cpu %s. Available cpu to manage this card are %s'
                  % (util.cpu_list_to_string(fp_mac.get_network_used_cpu(pci_nb)),
                     util.cpu_list_to_string(available_cpu)))

        print ' B - Back'
        print ' D - Delete selection'
        print ' X-Y,Z - Select cores to poll the card (X-Y,Z : select cores X to Y and Z)'
        print
        ans = raw_input('Enter selection: ')
        if (ans == 'b') or (ans == 'B') or (ans == ''):
            break
        if (ans == 'd') or (ans == 'D'):
            fp_mac.cpu_update(pci_nb, [])
        else:
            entry_list = util.get_cpu_list(ans, available_cpu)
            if entry_list:
                fp_mac.cpu_update(pci_nb, entry_list)
            else:
                raw_input('Invalid selection. Press enter to continue')


def _pcicard_menu(fp_mac, fpconf_fullname, clear_mode):
    while True:
        util.clear(clear_mode)
        print 'Network port selection'
        print '======================'
        print
        print 'B - back\n'

        for i in range(0, fp_mac.pci_network_count):
            name = fp_mac.get_network_name(i)
            eth = fp_mac.get_network_eth(i)
            cpulist = util.cpu_list_to_string(fp_mac.get_network_used_cpu(i))
            if eth == 'none':
                mount_info = '(not mounted on any eth) '
            else:
                mount_info = 'mounted on %s ' % eth
            if cpulist == '':
                cpu_info = 'not selected'
            else:
                cpu_info = 'selected with cores %s' % cpulist
            print '%d - %s PCI card %s%s' % (i + 1, name, mount_info, cpu_info)

        ans = raw_input('Enter selection: ')
        if (ans == 'b') or (ans == 'B') or (ans == ''):
            break
        else:
            if ((ans.isdigit() == False) or
                    (int(ans) > fp_mac.pci_network_count)):
                raw_input('Invalid selection. Press enter to continue')
            else:
                _edit_ethcard(fp_mac, int(ans) - 1, clear_mode)

def _main_menu(fp_mac, fp_mem, fpconf_fullname, clear_mode):
    while True:
        util.clear(clear_mode)
        print 'Fast path configuration'
        print '======================='
        print
        print 'C - Select hardware cryptographic accelerator'
        print 'N - Select network port'
        print
        print 'D - display configuration'
        print 'S - save configuration and exit'
        print 'Q - quit'
        print

        ans = raw_input('Enter selection: ')
        if (ans == 'q') or (ans == 'Q'):
            break
        if (ans == 'c') or (ans == 'C'):
            _edit_cryptocard(fp_mac, fp_mem, clear_mode)
        elif (ans == 'n') or (ans == 'N'):
            _pcicard_menu(fp_mac, fpconf_fullname, clear_mode)
        elif (ans == 's') or (ans == 'S') or (ans == 'd') or (ans == 'D'):
            fp_param = params.generate_parameter(fp_mac, fp_mem)
            if (ans == 'd') or (ans == 'D'):
                util.clear(clear_mode)
                print fp_param
                print
                raw_input('Press enter to continue')
            else:
                f = open(fpconf_fullname, 'w')
                f.write(str(fp_param))
                f.close()
                break
        else:
            raw_input('Invalid selection. Press enter to continue')

# --------------------------- main --------------------------------------------
def main():
    clear_mode = 1

    parser = argparse.ArgumentParser(description='Create, check and display fast'
                                     ' path configuration file. Without any '
                                     'arguments display information about '
                                     'selected crypto and PCI ethernet cards')

    parser.add_argument('-c', '--check',
                        action='store_true',
                        help='Check existing configuration')
    parser.add_argument('-f',
                        dest='file',
                        help='Specify fullname (path + name) of the fastpath '
                             'configuration file to create or check. '
                             'Default path is specified by the environment '
                             'variable CONF_FILE_fast_path or set to '
                             '/usr/local/etc/fast-path.env')
    parser.add_argument('-i', '--interact',
                        action='store_true',
                        help='Update configuration with end-user interactions')
    parser.add_argument('-m', '--machinedisplay',
                        action='store_true',
                        help='Display machine information')
    parser.add_argument('-n', '--new',
                        action='store_true',
                        help='Create new configuration (erase old one if exist)')
    parser.add_argument('--noclear',
                        action='store_true',
                        help='Do not clear console on user interaction')

    args = parser.parse_args()

    fp_mac = machine.scan_machine()

    if args.machinedisplay:
        print fp_mac
        sys.exit(0)

    fp_mem = memory.parse_fp_options()

    if args.file:
        fpconf_fullname = args.file
    else:
        fpconf_fullname = os.getenv('CONF_FILE_fast_path',
                                    '/usr/local/etc/fast-path.env')

    if args.noclear:
        clear_mode = 0

    if not args.new or args.check:
        fp_param = params.read_config(fpconf_fullname)
        errors = fp_mac.update_with_config(fp_param, fp_mem)

    if args.check:
        print 'Check configuration'
        print '==================='
        print
        need_conf = params.generate_parameter(fp_mac, fp_mem)
        params.check_config(fp_param, need_conf, errors)
        sys.exit(0)

    if args.interact:
        fp_mac.clean_config()
        _main_menu(fp_mac, fp_mem, fpconf_fullname, clear_mode)
    else:
        fp_mac.show()

#------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
