#!/usr/bin/python
'''
Gather system information regarding spectre and meltdown. 

Presumptions:
  Kernel 4.14 is safe: http://www.kroah.com/log/blog/2018/01/06/meltdown-status/
  Xen 4.8 and 4.10 are safe, 4.6 and 4.7 are not: https://blog.xenproject.org/2018/01/04/xen-project-spectremeltdown-faq/
'''

import os
import sys
import subprocess
import pprint
import logging
import re
import platform
import argparse

log = None

#
# Kernel Version that are known to be safe
#
KERNEL_VERSIONS = {
    'Debian': [],
    'Redht': [],
    'CentOS': [],
    'Custom': []
}

#
# A big map of systems with their required versions to be safe for meltdown/spectre
#
SYS_MAP = {
    # ALL DELL R2xx Models
    'PowerEdge R210': {
        'bios_version': None,
    },
    'PowerEdge R210 II': {
        'bios_version': None,
    },

    'PowerEdge R220': {
        'bios_version': '1.10.1',
    },

    # ALL DELL R4xx Models
    'PowerEdge R410': {
        'bios_version': None,
    },

    'PowerEdge R420': {
        'bios_version': None,
    },

    # ALL DELL R5xx Models
    'PowerEdge R510': {
        'bios_version': None,
    },
    'PowerEdge R515': {
        'bios_version': None,
    },

    # ALL DELL R6xx Models
    'PowerEdge R610': {
        'bios_version': None,
    },

    # ALL DELL R7xx Models
    'PowerEdge R710': {
        'bios_version': None,
    },
    'PowerEdge R720': {
        'bios_version': None,
    },
    'PowerEdge R720xd': {
        'bios_version': None,
    },
    'PowerEdge R730xd': {
        'bios_version': None,
    },

    # ALL DELL R8xx Models
    'PowerEdge R815': {
        'bios_version': None,
    },

    # ALL HP DL1xx
    'ProLiant DL160 Gen9': {
        'bios_version': None,
    },

    # ALL HP :DL3xx
    'ProLiant DL380 Gen9': {
        'bios_version': '2.54_12-07-2017(A)(5 Jan 2018)',
    },
}
class ArgParser(object):
    '''
    '''

    def __init__(self):
        self.main_parser = argparse.ArgumentParser()
        self.addArgs()
        self.verbose = False

    def addArgs(self):

        self.main_parser.add_argument(
            '--use-uname-r',
            type=bool,
            default=False,
            dest='use_uname_r',
            nargs='?',
            const=True,
            required=False,
            help='Use uname -r instead if pythons platform.uname()'
        )

#        self.main_parser.add_argument(
#            '-p',
#            type=int,
#            default=1,
#            const=True,
#            dest='priority',
#            nargs='?',
#            required=False,
#            help='Set job priority'
#        )

        self.main_parser.add_argument(
            '-d',
            type=bool,
            default=False,
            const=True,
            dest='debug',
            nargs='?',
            required=False,
            help='Output debug messages'
        )

    def parseArgs(self):
        return self.main_parser.parse_args()


class MyLogger(object):
    '''
    Simple logging class
    '''
    def __init__(self, level=logging.DEBUG):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level)
        ch_format = logging.Formatter('%(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(ch_format)
        ch.setLevel(level)
        self.logger.addHandler(ch)

    def info(self, msg):
        self.logger.info(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)

#
# HELPER FUNCTIONS FOR ANALYZING A SINGLE SYSTEM
#

def _check_bios_version(wversion, cversion):
    log_str = 'Checking bios version:'

    if wversion == cversion:
        log_str += '{0} == {1}, OK!'.format(wversion, cversion)
        log.info(log_str)
    else:
        log_str += '{0} != {1}, FAILED!'.format(wversion, cversion)
        log.info(log_str)
   

def _analyze(wdata):
    '''
    Check the gathered versions against required versions
    '''
    #  create shortcut to platform data
    cdata = SYS_MAP[wdata['system_product_name']]
    kernel_version = KERNEL_VERSIONS[wdata['os_release']]

    _check_bios_version(wdata['bios_version'], cdata['bios_version'])

#
# HELPER FUNCTIONS TO PARSE/EDIT DATA THAT CANT BE USED AS IS
# FROM STDOUT/STDERR LIKE 'dmidecode -s processer-version'
# WHICH RETURNS MORE THAN ONE LINE/VALUE
#
def _get_os_release():
    return platform.dist()[0].title()

def _get_processor_info():
    '''
    Gather processor model and version, only use first line since
    we cant play mix and match with different processors on a single
    board.
    '''
    log.info('Gathering processor information')
    retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'processor-version'])
    if retcode == 0:
        return stdout.split('\n')[0]
    else:
        return stderr


def _get_microcode_info():
    '''
    Gather microcode versions for installed cpus. Relies
    on Intels iucode-tool and amds <something>-tool.
    '''
    log.info('Gathering microcode version information')
    proc = _get_processor_info()

    if re.match('^.*xeon.*$', proc, re.I):
        log.debug('Getting microcode version with intels iucode-tool...')
        retcode, stdout, stderr = _run_cmd(['/usr/sbin/iucode-tool', '-S'])
       
        # The iucode-tool returns its data on stderr
        if retcode == 0 and len(stderr) > 0:
            return stderr.split()[-1]

    elif re.match('^.*opteron.*$', proc, re.I):
        log.debug('Getting microcode with amd tool...')
        return 'amd_version'
    else:
        return 'unknown'

def _get_system_product():
    '''
    Get system-product-name with dmidecode
    '''
    log.info('Gathering system-product information')
    retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'system-product-name'])
    
    if retcode == 0:
        if stdout.strip() in SYS_MAP:
            return stdout
        else:
            return 'system not supported'
    else:
        return stderr


def _get_bios_info():
    '''
    Gather bios versions from dell hp servers
    '''
    log.info('Gathering bios version information')
    sysprod = _get_system_product()

    # Dell has its version available in dmidecode
    if re.match('^poweredge.*$', sysprod, re.I):
        retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'bios-version'])

    # HP only has crap in dmidecode data, but ipmitool seems wto work
    elif re.match('^proliant.*$', sysprod, re.I):
        retcode, stdout, stderr = _run_cmd(['/usr/bin/ipmitool', 'mc', 'info'])

        for line in stdout.split('\n'):
            if re.match('^Firmware Revision\s+:.*$', line):
                return line.split()[3]
        return 'unknown'
    else:
        return 'system not supported'


def _get_xen_info():
    '''
    Gather xen-version, supports xl and xm for older versions.
    If your binary is located somewhere else, it might be easier
    to create a temporary symlink to the paths used here.
    '''
    log.info('Gathering xen version information')
    if os.path.isfile('/usr/sbin/xl'):
        XEN_BIN = '/usr/sbin/xl'
    elif os.path.isfile('/usr/sbin/xm'):
        XEN_BIN = '/usr/sbin/xm'
    else:
        log.info('No xm/xl binary found, skipping xen checks!')
        return False, False, False

    retcode, stdout, stderr = _run_cmd([XEN_BIN, 'info'])

    if retcode == 0 and len(stdout) > 0:
       for line in stdout.split('\n'):
           if re.match('^xen_version\s+:.*$', line):
               return line.split()[2]
    else:
        return stderr


def _run_cmd(cmd):
    '''
    Run arbitrary commands
    '''
   
    if not os.path.isfile(cmd[0]) or not os.access(cmd[0], os.X_OK):
        raise IOError('{0} does not exist or is not executable!'.format(cmd[0]))

    try:
        kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='.'
        )

#        log.debug('Executing command \'{0}\''.format(cmd))
        process = subprocess.Popen(cmd, **kwargs)

        stdout, stderr = process.communicate()

        return (process.returncode, stdout.strip(), stderr.strip())

    except OSError as os_err:
        raise

def _preflight():
    '''
    Some minor checks to save time and work
    '''
    sysprod = _get_system_product()
    if sysprod not in SYS_MAP:
        log.error('System type {0} is NOT yet supported'.format(sysprod))
        sys.exit(1)
    else:
        log.info('System type {0} is supported, continue'.format(sysprod))
    

#
# END OF HELPER FUNCTIONS
#


def main():
    ret = {}
    
    for name, cmd in CMD.iteritems():

        try:
            if isinstance(cmd, list):
                retcode, stdout, stderr = _run_cmd(cmd) 

                # a function that returns False, False, False is skipped
                if not retcode and not stdout and not stderr:
                    continue

                if retcode == 0:
                    ret.update({name: stdout})
                else:
                    ret.update({name: stderr})

            elif callable(cmd):
                ret.update({name: CMD[name]()})
 
        except (IOError, OSError) as xerr:
            ret.update({name: str(xerr)})

    log.info('Gathered data: {0}'.format(ret))
    return _analyze(ret)

if __name__ == '__main__':

    log = MyLogger()
    _preflight()

    # THE COMMANDS WE WANT TO RUN TO GATHER THE REQUIRED DATA.
    # WE EITHER CALL COMMANDS DIRECTLY OR CALL A FUNCTIION THAT
    # PARSES THE DATA BEFORE RETURNING IT.
    CMD = {
        'hostname': ['/bin/hostname'],
        'bios_version': _get_bios_info,
        'os_release': _get_os_release,
        'cpu_type': _get_processor_info,
        'microcode_version': _get_microcode_info,
        'xen_version': _get_xen_info,
        'kernel_version': ['/bin/uname', '-r'],
        'system_product_name': _get_system_product
    }

    pprint.pprint(main())
