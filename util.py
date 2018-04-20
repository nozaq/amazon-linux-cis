import logging
import os
from subprocess import check_output, CalledProcessError

__file_history__ = {}
__backup_enabled__ = True

def set_backup_enabled(flag):
    global __backup_enabled__
    __backup_enabled__ = flag

def exec_shell(cmd):
    """Executes consecutive shell commands."""
    if isinstance(cmd, str):
        cmd = [cmd]

    command_string = ' && '.join(cmd)

    logging.debug('Executing "%s"...', command_string)
    return check_output(command_string, shell=True)


def ensure_backed_up(path):
    """Backs up a file at the specified path unless it is already backed up"""
    global __file_history__
    global __backup_enabled__

    if not __backup_enabled__:
        return

    if path not in __file_history__ and os.path.isfile(path):
        backup_path = '{}.bak'.format(path)
        logging.info('Backing up %s into %s...', path, backup_path)
        exec_shell('cp {} {}'.format(path, backup_path))
        __file_history__[path] = True


class Service:
    """Represents a system service."""

    def __init__(self, name):
        self.name = name

    def exists(self):
        """Checks if the specified service exists."""
        try:
            exec_shell(['chkconfig --list {} &> /dev/null'.format(self.name)])
        except CalledProcessError:
            return False
        return True

    def enable(self):
        """Set the service to be started on startup."""
        if self.exists():
            exec_shell(['chkconfig {} on'.format(self.name)])

    def disable(self):
        """Set the service not to be started on startup."""
        if self.exists():
            exec_shell(['chkconfig {} off'.format(self.name)])


class Package:
    """Represents a yum package"""

    @staticmethod
    def update_all():
        """Updates all installed packages"""
        exec_shell(['yum update -y'])

    def __init__(self, name):
        self.name = name

    def exists(self):
        """Checks if the specified package is installed."""
        try:
            exec_shell(
                ['yum -q list installed {} &> /dev/null'.format(self.name)])
        except CalledProcessError:
            return False

        return True

    def install(self):
        """Installs the package."""
        if not self.exists():
            exec_shell(['yum install -y {}'.format(self.name)])

    def remove(self):
        """Removes the package."""
        if self.exists():
            exec_shell(['yum remove -y {}'.format(self.name)])


class File:
    """Represents a general file"""

    def __init__(self, path):
        self.path = path

    def write(self, content):
        """Writes a content into the ile"""
        ensure_backed_up(self.path)
        with open(self.path, 'w') as f:
            f.write(content)


class PropertyFile:
    """Represents a property file which contains a collection of key / value pairs"""

    def __init__(self, path, sep):
        self.path = path
        self.sep = sep
        self.params = {}

    def override(self, params):
        """Updates key / value pairs to be overridden"""
        for key, value in params.items():
            self.params[key] = value
        return self

    def write(self):
        """Writes a content with overridden key / value pairs into disk"""
        params = self.params.copy()
        content = ''

        if os.path.isfile(self.path):
            with open(self.path, 'r') as f:
                for line in f:
                    for key, value in params.items():
                        if line.startswith('{}{}'.format(key, self.sep)):
                            if value is not None:
                                line = '{}{}{}\n'.format(key, self.sep, value)
                            else:
                                line = ''
                            params.pop(key)
                    content += line

        for key, value in params.items():
            if value is not None:
                content += '\n{}{}{}'.format(key, self.sep, value)

        ensure_backed_up(self.path)
        with open(self.path, 'w') as f:
            f.write(content)
