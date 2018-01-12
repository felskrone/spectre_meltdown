#!/usr/bin/python
'''
Gather system information regarding spectre and meltdown.
'''

import os
import sys
import subprocess
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
# Kernel 4.14.11 is safe: http://www.kroah.com/log/blog/2018/01/06/meltdown-status/
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
    'Ubuntu': [],
    'CentOS': [],
    'Mainline': [
        '4.14.11',    # Mainlinr
        '4.15-rc6',   # Devel
        '4.9.75',     # 4.9 LTS
        '4.4.110'     # 4.4 LTS
    ],
    'Custom': []
}

#
# This is a list of update files released by intel on 2018-01-08:
# https://downloadcenter.intel.com/download/27431/Linux-Processor-Microcode-Data-File?product=40711
# According to the releases notes, the files are named in 'family-model-stepping'-pattern.
# By mapping the current processor to this files, we can tell, whether or not an update is
# available. That does NOT tell us, if we are already running a safe version!
INTEL_MCFILES = [
    '06-03-02', '06-05-00', '06-05-01', '06-05-02', '06-05-03', '06-06-00',
    '06-06-05', '06-06-0a', '06-06-0d', '06-07-01', '06-07-02', '06-07-03',
    '06-08-01', '06-08-03', '06-08-06', '06-08-0a', '06-09-05', '06-0a-00',
    '06-0a-01', '06-0b-01', '06-0b-04', '06-0d-06', '06-0e-08', '06-0e-0c',
    '06-0f-02', '06-0f-06', '06-0f-07', '06-0f-0a', '06-0f-0b', '06-0f-0d',
    '06-16-01', '06-17-06', '06-17-07', '06-17-0a', '06-1a-04', '06-1a-05',
    '06-1c-02', '06-1c-0a', '06-1d-01', '06-1e-05', '06-25-02', '06-25-05',
    '06-26-01', '06-2a-07', '06-2d-06', '06-2d-07', '06-2f-02', '06-3a-09',
    '06-3c-03', '06-3d-04', '06-3e-04', '06-3e-06', '06-3e-07', '06-3f-02',
    '06-3f-04', '0f-06-08', '06-56-02', '06-56-03', '06-9e-09', '06-9e-0a',
    '06-45-01', '06-46-01', '06-47-01', '06-4e-03', '06-4f-01', '06-55-04', 
    '06-56-04', '06-5c-09', '06-5e-03', '06-7a-01', '06-8e-09', '06-8e-0a',
    '06-9e-0b', '0f-00-07', '0f-00-0a', '0f-01-02', '0f-02-04', '0f-02-05',
    '0f-02-09', '0f-03-02', '0f-03-03', '0f-03-04', '0f-04-01', '0f-04-03',
    '0f-04-08', '0f-04-09', '0f-04-0a', '0f-06-02', '0f-06-04', '0f-06-05',
    '0f-02-06', '0f-02-07','0f-04-04', '0f-04-07'
]

#
# A mapping of processor types to know good microcode version. For now it is assumed,
# that each Xeon E-generation has the same microcode version. For example all Xeons v3
# have '0x3b' and all Xeon v4 have '0xb000025'. If this turns out to be wrong, this will
# be changed. The available versions are taken from wikipedia
# https://en.wikipedia.org/wiki/Xeon#Sandy_Bridge%E2%80%93_and_Ivy_Bridge%E2%80%93based_Xeon
#
# False stands for a yet unknown version.

#
MC_CPU_MAP = {
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(v6).*$': False,   # Xeon E5 v6
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(v5).*$': False,   # Xeon E5 v5
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(v4).*$': '0xb000025',   # Xeon E5 v4
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(v3).*$': '0x3b',        # Xeon E5 v3
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(v2).*$': False,         # Xeon E5 v2
    '^Intel\(R\) Xeon\(R\) CPU E5-\d+\s+(0).*$': False,          # Xeon E5 0
    '^Intel\(R\) Xeon\(R\) CPU\s+X\d+\s+.*$': False,             # Xeon Xxxxx, versionless
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
# False stands for a yet unknown version.
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
    'ProLiant DL380 G6': {
        'bios_version': '2.54'
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
            '--iucode-path',
            type=str,
            default='/usr/sbin/iucode-tool',
            dest='iucodetool',
            nargs='?',
            help='Path to Intels iucode-tool to retrieve current microcode version'
        )

        self.main_parser.add_argument(
            '--out',
            type=str,
            default='colored',
            dest='otype',
            nargs='?',
            choices=['raw','short','json', 'colored'],
            required=False,
            help=(
                'Select your desired output put (default: colored) '
                'colored=colored with OK/FAILED on result/line '
                'raw=python dictionary pretty printed to stdout '
                'short=bios,kernel,microcode,xen (if present) status '
                'json=jsondump of python dict'
            )
        )

        self.main_parser.add_argument(
            '--kernel-version-source',
            type=str,
            default=False,
            dest='kversion_src',
            choices=['uname-r', 'uname-v', 'proc_signature'],
            nargs='+',
            required=False,
            help='Get kernel version with uname -r/-v, the latter is required for debian and ubuntu'
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

        if level != None and level in [logging.INFO, logging.DEBUG]:
            self.logger.setLevel(level)
            ch_format = logging.Formatter('%(levelname)s - %(message)s')
            ch = logging.StreamHandler()
            ch.setFormatter(ch_format)
            ch.setLevel(level)
            self.logger.addHandler(ch)
        else:
            try:
                self.logger.addHandler(logging.NullHandler())
            except AttributeError:
                # Fixes Redhat NullHandler-Exception, we dont want output anyway
                pass

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
        log_str += 'xen version \'{0}\' found in Custom-versions, OK'.format(xversion)
        log.info(log_str)
        return True

    for cversion in XEN_VERSIONS['Main']:
        if version(xversion) >= version(cversion):
            log_str += 'xen version \'{0}\' >= \'{1}\', OK!'.format(xversion, cversion)
            log.info(log_str)
            return True

    msg = (
        '\'{0}\' not found in Xen-custom-versions '
        'and {0} < Xen-Main-versions, FAILED!'
    )
    log_str += msg.format(xversion)
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
        log_str += '\'{0}\' >= \'{1}\', OK!'.format(wversion, cdata['bios_version'])
        log.info(log_str)
        return True
    else:
        log_str += '\'{0}\' < \'{1}\', FAILED!'.format(wversion, cdata['bios_version'])
        log.info(log_str)
        return False


def _check_microcode_version(wversion, cpu_type, **kwargs):
    log_str = 'Checking microcode update status: '

    log.info(cpu_type)
    cpu_mc_name = '{0:02x}-{1:02x}-{2:02x}'.format(
        cpu_type['family'],
        cpu_type['model'],
        cpu_type['stepping']
    )

    if cpu_mc_name in INTEL_MCFILES:
        log_str += 'Update found (filename: {0})'.format(cpu_mc_name)
        log.info(log_str)
    else:
        log.info('No update file found, would be \'{0}\''.format(cpu_mc_name))

    try:
        cur_xeon_version = re.match(
            '^Intel.*\s(v[2-6]{1}|0)\s@.*$',
            cpu_type['plain'],
            re.I
        ).groups()[0]
    except (AttributeError, IndexError):
        log.debug('Processor \'{0}\' has no version, correct?'.format(cpu_type['plain']))

    for rgx, safe_version in MC_CPU_MAP.iteritems():
  
        if re.match(rgx, cpu_type['plain'], re.I):
            if wversion == safe_version:
                log.info('\'{0}\' == \'{1}\', Microcode for \'{2}\' is up2date, OK!'.format(
                        wversion,
                        safe_version,
                        cpu_type['plain']
                    )
                )
                return True

            else:
                log.info('\'{0}\' != \'{1}\', Microcode for \'{2}\' needs update, FAILED!'.format(
                        wversion,
                        safe_version,
                        cpu_type['plain']
                    )
                )
                return False

    log.error('No processor matched, cant say if microcode is up2date!')
    return False


def _check_kernel_version(wversion, distro):
    '''
    Check current kernel version against known good versions
    from distro list and custom kernel names.
    '''
    log_str = 'Checking kernel version: '
    safe_kernels = KERNEL_VERSIONS[distro]
    cust_kernels  = KERNEL_VERSIONS['Custom']

    # Steps:
    # 1. Check excact versions in KERNEL_VERSIONS['distro']
    # 2. Check excact versions in KERNEL_VERSIONS['Custom']
    # 3. Compare version to known safe mainline and LTS versions
    # 4. Fail if none of the above succeeded
    if wversion in safe_kernels:
        log_str += '\'{0}\' found in {0}-kernels, OK'.format(wversion, distro)
        log.info(log_str)
        return True

    elif wversion in cust_kernels:
        log_str += '\'{0}\' found in Custom-kernels, OK'.format(wversion, distro)
        log.info(log_str)
        return True

    else:

        for ml_version in KERNEL_VERSIONS['Mainline']:
            if version(wversion) >= version(ml_version):
                log_str += '\'{0}\' >= \'{1}\' from Mainline/LTS, OK!'.format(wversion, ml_version)
                log.info(log_str)
                return True

        log_str += '\'{0}\' < \'{1}\' and its not in {2}- or Custom-kernel list, FAILED'.format(
           wversion, 
           KERNEL_VERSIONS['Mainline'],
           distro
        )
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
    Get the kernel version. The exact version has different sources:
        Debian: 'uname -v', 'uname -r' is just the package version
        Ubuntu: '/proc/version_signature', uname only tells package version
        Redhat/CentOS: uname -r, package version corresponds with this
    '''
    log.info('Gathering kernel version information')

    # Get os-release and determine the way to retrieve kernel version
    # if the user has not given us directions on how to do it
    osr = _get_os_release()

    if not kwargs['kversion_src']:
        if re.match('^debian$', osr, re.I):
            kversion_src = 'uname-v'
        elif re.match('^ubuntu$', osr, re.I):
            kversion_src = 'proc_signature'
        elif re.match('^(redhat|centos)$', osr, re.I):
            kversion_src = 'uname-r'
        else:
            return 'Distro {0} is not supported'.format(osr)
    else:
        kversion_src = kwargs['kversion_src'][0]

    if kversion_src == 'uname-r':
        retcode, stdout, stderr = _run_cmd(['/bin/uname' ,'-r'])
    elif kversion_src == 'uname-v':
        retcode, stdout, stderr = _run_cmd(['/bin/uname' ,'-v'])
    elif kversion_src == 'proc_signature':
        try:
            ret = _readfile('/proc/version_signature').strip()
            return ret.split()[2]
        except (IOError, OSError) as readerr:
            return 'Failed to get kernel version: {0}'.format(readerr)
    else:
        return 'Failed to get kernel version: {0}'.format(readerr)

    if retcode == 0:
        if kversion_src == 'uname-v':
            kversion = stdout.split()[3]
            kversion = '3.2.63-2+deb7u2'
            if re.match('^(\d+)\.(\d+)\.(\d+)-.*$', kversion):
                return kversion
            else:
                return 'Failed to parse \'uname -v\' output for kernel version'
        else:
            return stdout
    else:
        return stderr


def _get_microcode_info(**kwargs):
    '''
    Gather microcode versions for installed cpus. Relies
    on Intels iucode-tool and amds <something>-tool.
    '''
    log.info('Gathering microcode version information')
    cpu_details = _get_processor_info()

    if re.match('^.*xeon.*$', cpu_details['plain'], re.I):
        log.debug('Getting microcode version with intels iucode-tool...')
        retcode, stdout, stderr = _run_cmd([kwargs['iucodetool'], '-S'])

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
        return 0

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
        print(data)

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

                # Command was successfully, add the return
                if retcode == 0:
                    sysdata.update({name: stdout})
                else:
                    sysdata.update({name: stderr})

            # Execute the callable and use the returned data is
            elif callable(cmd):

                call_data = CMD[name](**args)

                # Results of callables returning a single 0
                # are skipped completely from the results. For
                # example is xen is not installed at all
                if call_data == 0:
                    continue
                else:
                    sysdata.update({name: call_data})

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


