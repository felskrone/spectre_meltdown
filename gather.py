#!/usr/bin/python
'''
Gather system information regarding spectre and meltdown
'''

import os
import sys
import subprocess
import pprint
import logging
import re

log = None

class MyLogger(object):
    '''
    Basic logging class for easy logging to a custom
    file and to the console
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
# HELPER FUNCTIONS TO PARSE/EDIT DATA THAT CANT BE USED AS IS
# FROM STDOUT/STDERR LIKE 'dmidecode -s processer-version'
# WHICH RETURNS MORE THAN ONE LINE/VALUE
#
def _get_processor_info():
    retcode, stdout, stderr = run_cmd(['/usr/sbin/dmidecode', '-s' 'processor-version'])
    if retcode == 0:
        print stdout
        return set(stdout)
    else:
        return stderr

def _get_xen_info():
    if os.path.isfile('/usr/sbin/xl'):
        XEN_BIN = '/usr/sbin/xl'
    elif os.path.isfile('/usr/sbin/xm'):
        XEN_BIN = '/usr/sbin/xm'
    else:
        raise IOError('No xl/xm binary found')

    retcode, stdout, stderr = run_cmd([XEN_BIN, 'info'])
    if retcode == 0 and len(stdout) > 0:
       for line in stdout:
           if re.match('^xen_version\s+:.*$', line):
               return line.split()[2]
    else:
        return stderr



def run_cmd(cmd):
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

        process = subprocess.Popen(cmd, **kwargs)

        stdout, stderr = process.communicate()

        return (process.returncode, stdout.strip(), stderr.strip())

    except OSError as os_err:
        raise

def main():
    ret = {}
    
    for name, cmd in CMD.iteritems():

        try:
            if isinstance(cmd, list):
                log.debug('Running list-command {0}'.format(cmd))
                retcode, stdout, stderr = run_cmd(cmd) 

                if retcode == 0:
                    # intels iucode_tool returns its data on stderr
                    ret.update({name: stdout})
                else:
                    ret.update({name: stderr})

            elif callable(cmd):
                log.debug('Running callable {0}'.format(cmd))
                ret.update({name: CMD[name]()})
 
        except (IOError, OSError) as xerr:
            ret.update({name: str(xerr)})

    return ret


if __name__ == '__main__':

    # THE COMMANDS WE WANT TO RUN TO GATHER THE REQUIRED DATA.
    # WE EITHER CALL COMMANDS DIRECTLY OR CALL A FUNCTIION THAT
    # PARSES THE DATA BEFORE RETURNING IT.
    CMD = {
        'hostname': ['/bin/hostname'],
        'bios_version': ['/usr/sbin/dmidecode', '-s', 'bios-version'],
        'cpu_type': _get_processor_info,
        'xen_version': _get_xen_info,
        'kernel_version': ['/bin/uname', '-r'],
        'system_product_name': ['/usr/sbin/dmidecode', '-s', 'system-product-name']
    }

    log = MyLogger()
    pprint.pprint(main())
