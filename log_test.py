import sys,os
PWD = os.path.dirname(os.path.abspath(__file__))
# print PWD
import argparse, socket
import logging

# def parse_args():
    # parser = argparse.ArgumentParser(description="zkServer manager")

    # parser.add_argument("--daemon",  '-d', action='store_true',  help="run as daemon manager")
    # parser.add_argument("--force", "-f",  action='store_true',  help="force start as daemon")
    # parser.add_argument("--msg", '-m', type=str, default=None, help="zkMonitor message")
    # parser.add_argument('--verbose', '-v', default=LOG_CHOICE[1], choices = LOG_CHOICE, help="log level")

    # return parser.parse_args()

LOG_LEVEL = (logging.NOTSET, logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL)
LOG_CHOICE = map(lambda x: logging.getLevelName(x), LOG_LEVEL)
def set_loggint_format(level):
    debug_info = " %(filename)s:%(lineno)d" if level in [LOG_CHOICE[0], LOG_CHOICE[1]] else ""

    logging.basicConfig(
        level=level,
        format='[%(asctime)s %(levelname)s]:' + debug_info + ' %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


if __name__ == '__main__':
    # args = parse_args()
    # print args
    # print args.daemon
    # print args.msg

    set_loggint_format(1)
    


    logging.info("gfhgfhgh")



