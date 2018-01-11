#!/usr/bin/python
'''
Gather system information regarding spectre and meltdown.
'''

import os
import sys
import subprocess
import pprint
import logging
import re
import platform
import argparse
import json
from distutils.version import LooseVersion as version

log = None

#
# Kernel Versions that are known to be safe
# Presumptions:
# Kernel 4.14 is safe: http://www.kroah.com/log/blog/2018/01/06/meltdown-status/
#
KERNEL_VERSIONS = {
    'Debian': [
        # Source: https://security-tracker.debian.org/tracker/CVE-2017-5754
        '3.2.96-3-amd64',    # wheezy
        '3.16.51-3-amd64',   # jessie
        '4.9.65-3-amd64',    # stretch
        '4.14.12-2-amd64'    # sid
    ],
    'Redhat': [
        '3.10.0-693.11.6.x86_64',  # CentOS/RHEL7
        '2.6.32-696.18.7.el6',     # CentOS/RHEL6
    ],
    'CentOS': [],
    'Custom': [
        '4.14'
    ]
}

#
# This is a list of updates files released by intel on 20180108:
# https://downloadcenter.intel.com/download/27431/Linux-Processor-Microcode-Data-File?product=40711
# According to the releases notes, the files are named in 'family-model-stepping'-pattern.
# By mapping the current processor to this files, we can tell, whether or not an update is
# available.
#
MC_VERSIONS = {
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+v4.*$': '0xb000025',
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+v3.*$': '0x3b',
}

#
# A list of known to be safe xen-versions
# Presumptions:
#     Xen 4.8 and 4.10 are safe, xen < 4.7 are not: https://blog.xenproject.org/2018/01/04/xen-project-spectremeltdown-faq/
#
XEN_VERSIONS = {
    'Custom': [],
    'Main': [
        '4.8',
        '4.10'
    ]
}

#
# A mapping of system-product name to its safe bios version
#
BIOS_VERSIONS = {
    # ALL DELL R2xx Models
    'PowerEdge R210': {
        'bios_version': False,
    },
    'PowerEdge R210 II': {
        'bios_version': False,
    },

    'PowerEdge R220': {
        'bios_version': '1.10.1',
    },

    # ALL DELL R4xx Models
    'PowerEdge R410': {
        'bios_version': False,
    },

    'PowerEdge R420': {
        'bios_version': False,
    },
    'PowerEdge R430': {
        'bios_version': '2.7.0',
    },
    'PowerEdge T430': {
        'bios_version': '2.7.0',
    },

    # ALL DELL R5xx Models
    'PowerEdge R510': {
        'bios_version': False,
    },
    'PowerEdge R515': {
        'bios_version': False,
    },
    'PowerEdge R530': {
        'bios_version': '2.7.0',
    },

    # ALL DELL R6xx Models
    'PowerEdge R610': {
        'bios_version': False,
    },
    'PowerEdge R630': {
        'bios_version': '2.7.0',
    },

    # ALL DELL R7xx Models
    'PowerEdge R710': {
        'bios_version': False,
    },
    'PowerEdge R730': {
        'bios_version': '2.7.0'
    },
    'PowerEdge R730xd': {
        'bios_version': '2.7.0',
    },

    # ALL DELL R8xx Models
    'PowerEdge R815': {
        'bios_version': False,
    },

    # ALL HP DL1xx
    'ProLiant DL120 Gen9': {
        'bios_version': '2.54',
    },
    'ProLiant DL160 Gen9': {
        'bios_version': '2.54',
    },
    'ProLiant DL165 G7': {
        'bios_version': False,
    },
    'ProLiant DL180 Gen9': {
        'bios_version': '2.54',
    },

    # ALL HP DL3xx
    'ProLiant DL320e Gen8': {
        'bios_version': '2017.12.12',
    },
    'ProLiant DL360 Gen8': {
        'bios_version': False,
    },
    'ProLiant DL360e Gen9': {
        'bios_version': '2.54',
    },
    'ProLiant DL380 Gen9': {
        'bios_version': '2.54'
    }
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
            help='Use uname -r instead if pythons platform.uname() (default: False)'
        )

        self.main_parser.add_argument(
            '--out',
            type=str,
            default='raw',
            dest='otype',
            nargs='?',
            choices=['raw','short','json', 'colored'],
            required=False,
            help=(
                'Select your desired output put (default: raw) '
                'colored=colored with OK/FAILED on result/line '
                'raw=python dictionary pretty printed to stdout '
                'short=bios,kernel,microcode,xen (if present) status '
                'json=jsondump of python dict'
            )
        )

        self.main_parser.add_argument(
            '--intel-updates-directory',
            type=str,
            default='',
            dest='intel_updates_dir',
            nargs='+',
            required=False,
            help='The directory containing intel microcode updates (default: ./intel-ucode)'
        )

        self.main_parser.add_argument(
            '-v',
            type=bool,
            default=False,
            const=True,
            dest='verbose',
            nargs='?',
            required=False,
            help='Show whats being done (default: False)'
        )

        self.main_parser.add_argument(
            '-d',
            type=bool,
            default=False,
            const=True,
            dest='debug',
            nargs='?',
            required=False,
            help='Output debug messages (default: False)'
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
# Helper functions to analyze gathered data
#

def _check_xen_version(xversion, **kwargs):
    log_str = 'Checking xen version: '

    if xversion in XEN_VERSIONS['Custom']:
        log_str += 'xen version {0} found in Custom-versions, OK'.format(xversion)
        log.info(log_str)
        return True

    for cversion in XEN_VERSIONS['Main']:
        if version(xversion) >= version(cversion):
            log_str += 'xen version {0} >= {1}, OK!'.format(xversion, cversion)
            log.info(log_str)
            return True

    log_str += '{0} not found in Xen-Custom- and is {0} < Xen-Main-versions, FAILED!'.format(xversion)
    log.info(log_str)
    return False


def _check_bios_version(wversion, **kwargs):
    log_str = 'Checking bios version: '

    #  create shortcut to platform data
    cdata = BIOS_VERSIONS[kwargs['system_product_name']]

    if not cdata['bios_version']:
       msg = 'Cant check bios, no data for platform {0} available, FAILED!'
       log.error(msg.format(kwargs['system_product_name']))
       return False

    if version(wversion) > version(cdata['bios_version']):
        log_str += '{0} >= {1}, OK!'.format(wversion, cdata['bios_version'])
        log.info(log_str)
        return True
    else:
        log_str += '{0} < {1}, FAILED!'.format(wversion, cdata['bios_version'])
        log.info(log_str)
        return False

def _check_microcode_version(wversion, cpu_type, **kwargs):
    log_str = 'Checking microcode update status: '

    if  len(kwargs['intel_updates_dir']) > 0:
        if not os.path.isdir(str(kwargs['intel_updates_dir'])):
            log.error('Directory {0} not found, cant check microcodes updates, FAILED!'.format(
                    kwargs['intel_updates_dir']
                )
            )
            return False

        try:
            mc_files = os.listdir(kwargs['intel_updates_dir'])
        except (OSError, IOError):
            log.error('Failed to list directory {0}, cant check microcodes updates, FAILED!'.format(
                    kwargs['intel_updates_dir']
                )
            )
            return False

        cpu_mc_name = '{:02x}-{:02x}-{:02x}'.format(
            cpu_type['family'],
            cpu_type['model'],
            cpu_type['stepping']
        )

        for mcf in mc_files:
            if re.match(cpu_mc_name, mcf):
                log_str += 'Update found ({0})'.format(cpu_mc_name)
                log.info(log_str)
    else:
        log_str += 'no directory defined, skipping check!'
        log.info(log_str)

    log.info('TODO: check if update was applied!')
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

    cpu_details = {
        'plain': None,
        'model': None,
        'family': None,
        'stepping': None,
    }

    # Get processor type string
    retcode, stdout, stderr = _run_cmd(['/usr/sbin/dmidecode', '-s', 'processor-version'])

    if retcode == 0:
        cpu_details['plain'] = stdout.split('\n')[0]
    else:
        cpu_details['plain'] = stderr

    # Get family and stepping. Why not use a python-module? Dependencies...
    with open('/proc/cpuinfo', 'r') as cpuf:
        for ndx, l in enumerate(cpuf.readlines()):
            try:
                cpu_details['family'] = int(re.match('cpu family\s+:\s+(.*)$', l).groups()[0])
            except AttributeError as rgx_err:
                pass

            try:
                cpu_details['stepping'] = int(re.match('stepping\s+:\s+(.*)$', l).groups()[0])
            except AttributeError as rgx_err:
                pass

            try:
                cpu_details['model'] = int(re.match('model\s+:\s+(.*)$', l).groups()[0])
            except AttributeError as rgx_err:
                pass

           # break on second processor if present
            if l.startswith('processor    :') and ndx > 0:
                break

    if not cpu_details['model']:
        log.debug('Failed to extract model from current processor-info!')
    if not cpu_details['family']:
        log.debug('Failed to extract family from current processor-info!')
    if not cpu_details['stepping']:
        log.debug('Failed to extract stepping from current processor-info!')

    return cpu_details


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
    cpu_details = _get_processor_info()

    if re.match('^.*xeon.*$', cpu_details['plain'], re.I):
        log.debug('Getting microcode version with intels iucode-tool...')
        retcode, stdout, stderr = _run_cmd(['/usr/sbin/iucode-tool', '-S'])

        # The iucode-tool returns its data on stderr
        if retcode == 0 and len(stderr) > 0:
            return stderr.split()[-1]

    elif re.match('^.*opteron.*$', cpu_details['plain'], re.I):
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
            print('System {0} is not (yet) supported!'.format(stdout))
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
        return stdout

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

def _print(data, **kwargs):
    if kwargs['otype'] == 'raw':
        pprint.pprint(data)

    elif kwargs['otype'] == 'json':
        print(simplejson.dumps(data))

    elif kwargs['otype'] == 'short':
        out = []
        for k,v in sorted(data.items()):
            out.append(str(v))
        print(','.join(out))

    elif kwargs['otype'] == 'colored':
        colors = {
          'COLS': '\033[95m',
          'OKGREEN': '\033[92m',
          'FAILRED': '\033[91m',
          'ENDC': '\033[0m',
        }

        for k,v in data.items():
            if v:
                print('{0}{2}: {2}{3}'.format(
                        k,
                        colors['OKGREEN'],
                        v,
                        colors['ENDC']
                    )
                )
            else:
                print('{0}{1}: {2}{3}'.format(
                        k,
                        colors['FAILRED'],
                        v,
                        colors['ENDC']
                   )
                )



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

    log.debug('Parsed arguments: {0}'.format(args))

    _preflight()

    # The commands we want to run to gather data. We either call commands directly.
    # or call a function that parses/edits the data before returning it.
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

    sysdata = {}
    sysreport = {}

    for name, cmd in CMD.iteritems():

        try:
            if isinstance(cmd, list):
                retcode, stdout, stderr = _run_cmd(cmd)

                # A function that returns False, False, False is skipped. For
                # example _get_xen_info() does, if no xm/xl util is not found.
                if not retcode and not stdout and not stderr:
                    continue

                # Command was successfully, add the return
                if retcode == 0:
                    sysdata.update({name: stdout})
                else:
                    sysdata.update({name: stderr})

            # Execute the callable and use the returned data is
            elif callable(cmd):
                sysdata.update({name: CMD[name](**args)})

        # IF any command fails, add the returned error as result
        except (IOError, OSError) as xerr:
            sysdata.update({name: str(xerr)})

    log.debug('Gathered data: {0}'.format(sysdata))

    # Check the gathered versions against required versions
    sysreport['bios_version'] = _check_bios_version(sysdata['bios_version'], **sysdata)
    sysreport['kernel_version'] = _check_kernel_version(sysdata['kernel_version'], sysdata['os_release'])
    sysreport['microcode_version'] =_check_microcode_version(sysdata['microcode_version'], sysdata['cpu_type'], **args)

    if 'xen_version' in sysdata:
       sysreport['xen_version'] =_check_xen_version(sysdata['xen_version'])
    _print(sysreport, **args)


