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
    'Debian': [
        '3.2.96-3-amd64',    # wheezy
        '3.16.51-3-amd64',   # jessie
        '4.9.65-3-amd64',    # stretch
        '4.14.12-2-amd64'    # sid
    ],
    'Redhat': [],
    'CentOS': [],
    'Custom': [
        '4.4.74-1-xen0-he+'
    ]
}

# 
# This is a list of regexes that will be run against the value in
# __main__.ret['cpu_type']. That gets filled in _get_processor_info()
# and since the list of cpus being updated by intel is huge, you will
# most likely have to adjust/extend the regexes for the processors you
# are currently using.
#
MC_VERSIONS = {
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+v4.*$': '0xb000025',
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+v3.*$': '0x3b',
}

#
# A big map of systems with their required versions to be safe for meltdown/spectre
#
BIOS_VERSIONS = {
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

        self.main_parser.add_argument(
            '-v',
            type=bool,
            default=False,
            const=True,
            dest='verbose',
            nargs='?',
            required=False,
            help='Output progress info'
        )

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
    def __init__(self, level=None):
        self.logger = logging.getLogger(__name__)
        if level != None and level == logging.INFO or level == logging.DEBUG:
            self.logger.setLevel(level)
            ch_format = logging.Formatter('%(levelname)s - %(message)s')
            ch = logging.StreamHandler()
            ch.setFormatter(ch_format)
            ch.setLevel(level)
            self.logger.addHandler(ch)
        else:
            self.logger.addHandler(logging.NullHandler())

    def info(self, msg):
        self.logger.info(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)

#
# HELPER FUNCTIONS FOR ANALYZING A SINGLE SYSTEM
#

def _check_bios_version(wversion, cversion, **kwargs):
    log_str = 'Checking bios version: '

    if wversion == cversion:
        log_str += '{0} == {1}, OK!'.format(wversion, cversion)
        log.info(log_str)
        return True
    else:
        log_str += '{0} != {1}, FAILED!'.format(wversion, cversion)
        log.info(log_str)
        return False

def _check_microcode_version(wversion, cpu_type, **kwargs):
    log_str = 'Checking microcode version: '

    for rgx, safe_version in MC_VERSIONS.iteritems():
        log.debug('re-matching \'{0}\' against \'{1}\''.format(
                rgx,
                cpu_type
            )
        )
        if re.match(rgx, cpu_type):
            if wversion ==  safe_version:
                log_str += '{0} is up2date for {1}, OK'.format(
                    safe_version,
                    cpu_type
                )
                log.info(log_str)
                return True
            else:
                log_str += '{0} != {1} for {2}, FAILED'.format(
                    wversion,
                    safe_version,
                    cpu_type
                )
                log.error(log_str)
                return False
    log.error('Failed to match current cpu against known list, check regexes!')
    return False


def _check_kernel_version(wversion, distro):
    '''
    Check current kernel version against known good versions
    from distro list and custom kernel names.
    '''
    log_str = 'Checking kernel version: '
    safe_kernels = KERNEL_VERSIONS[distro]
    cust_kernels  = KERNEL_VERSIONS['Custom']

    if wversion in safe_kernels:
        log_str += '{0} found in {0}-kernels, OK'.format(wversion, distro)
        log.info(log_str)
        return True

    elif wversion in cust_kernels:
        log_str += '{0} found in Custom-kernels, OK'.format(wversion, distro)
        log.info(log_str)
        return True

    else:
        log_str += '{0} NOT found in {1}- or Custom-kernels, FAILED'.format(wversion, distro)
        log.info(log_str)
        return False
 
   

def _analyze(wdata, **kwargs):
    '''
    Check the gathered versions against required versions
    '''
    #  create shortcut to platform data
    cdata = BIOS_VERSIONS[wdata['system_product_name']]

    print(_check_bios_version(wdata['bios_version'], cdata['bios_version']))
    print(_check_kernel_version(wdata['kernel_version'], wdata['os_release']))
    print(_check_microcode_version(wdata['microcode_version'], wdata['cpu_type']))

#
# Helper functions to parse/edit data that cant be used as is
# from stdout/stderr like 'dmidecode -s processer-version'
# which returns more than one line/value.
#
def _get_os_release(**kwargs):
    return platform.dist()[0].title()

def _get_processor_info(**kwargs):
    '''
    Gather processor model and version, only use first line since
    we cant play mix and match with different processors on a single
    motherboard.
    '''
    log.info('Gathering processor information')
    retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'processor-version'])
    if retcode == 0:
        return stdout.split('\n')[0]
    else:
        return stderr

def _get_kernel_version(**kwargs):
    '''
    Get the kernel version from platform.uname or uname -r directly.
    '''
    log.info('Gathering kernel version information')

    distro = _get_os_release()

    if kwargs['use_uname_r']:
        retcode, stdout, stderr = _run_cmd(['/bin/uname', '-r'])
        if retcode == 0:
            return stdout
        else:
            return stderr
    elif re.match('^(debian|ubuntu)$', distro, re.I):
        return platform.uname()[3].split()[3]

    elif re.match('^(redhat|centos)$', distro, re.I):
        return platform.uname()[2]
    else:
        return 'Unable to retrieve kernel version, unknown distro?'
 

def _get_microcode_info(**kwargs):
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

def _get_system_product(**kwargs):
    '''
    Get system-product-name with dmidecode
    '''
    log.info('Gathering system-product information')
    retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'system-product-name'])
    
    if retcode == 0:
        if stdout.strip() in BIOS_VERSIONS:
            return stdout
        else:
            return 'system not supported'
    else:
        return stderr


def _get_bios_info(**kwargs):
    '''
    Gather bios versions from dell and hp servers
    '''
    log.info('Gathering bios version information')
    sysprod = _get_system_product()

    # Dell has its version available in dmidecode
    if re.match('^poweredge.*$', sysprod, re.I):
        retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'bios-version'])

    # HP only has crap in dmidecode data, but ipmitool seems to work
    elif re.match('^proliant.*$', sysprod, re.I):
        retcode, stdout, stderr = _run_cmd(['/usr/bin/ipmitool', 'mc', 'info'])

        for line in stdout.split('\n'):
            if re.match('^Firmware Revision\s+:.*$', line):
                return line.split()[3]
        return 'unknown'
    else:
        return 'system not supported'


def _get_xen_info(**kwargs):
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

        log.debug('Executing command \'{0}\''.format(cmd))
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
    if sysprod not in BIOS_VERSIONS:
        log.error('System type {0} is NOT yet supported'.format(sysprod))
        sys.exit(1)
    else:
        log.info('System type {0} is supported, continue'.format(sysprod))
    

#
# END OF HELPER FUNCTIONS
#

if __name__ == '__main__':
    args = vars(ArgParser().parseArgs())

    if args['debug']:
        log = MyLogger(level=logging.DEBUG)
    elif args['verbose']:
        log = MyLogger(level=logging.INFO)
    else:
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
        'kernel_version': _get_kernel_version,
        'system_product_name': _get_system_product
    }
    ret = {}

    for name, cmd in CMD.iteritems():

        try:
            if isinstance(cmd, list):
                retcode, stdout, stderr = _run_cmd(cmd) 

                # A function that returns False, False, False is skipped. For
                # example _get_xen_info() does, if no xm/xl util is not found.
                if not retcode and not stdout and not stderr:
                    continue

                if retcode == 0:
                    ret.update({name: stdout})
                else:
                    ret.update({name: stderr})

            elif callable(cmd):
                ret.update({name: CMD[name](**args)})
 
        except (IOError, OSError) as xerr:
            ret.update({name: str(xerr)})

    log.info('Gathered data: {0}'.format(ret))
    _analyze(ret)
