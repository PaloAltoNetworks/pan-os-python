import os
import sys


SPLUNK_HOME = os.environ.get('SPLUNK_HOME')


def run_by_splunk():
    """Check if this script was run by Splunk, or on the CLI

    :return: True if run by Splunk, otherwise False
    """
    env = os.environ.get('SPLUNK_SERVER_NAME')
    if env is None:
        return False
    else:
        return True


def init_logging(level=20):  # level 20 is logging.INFO
    if run_by_splunk():
        import splunk.mining.dcutils as dcu
        logger = dcu.getLogger()
    else:
        import logging
        logger = logging.getLogger()
        logger.setLevel(level)
        ch = logging.StreamHandler(sys.stdout)
        logger.addHandler(ch)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
    return logger


def init_splunk_environment(splunk_home):
    """Configure paths and env vars to support Splunk imports, even if script was run from CLI

    Only run this if you have already determined the SPLUNK_HOME and passed it as a parameter to this method.
    This method is not necessary if the script was run by Splunk.

    """
    if run_by_splunk():
        return
    # Set python path to include Splunk python libraries
    sys.path[:0] = [os.path.join(splunk_home, 'lib', 'python2.7', 'site-packages')]
    # Set SPLUNK_DB env variable which is used by some Splunk python libraries
    if os.environ.get('SPLUNK_DB') is None:
        os.environ['SPLUNK_DB'] = os.path.join(splunk_home, 'var', 'lib', 'splunk')
    # Set LD_LIBRARY_PATH to include Splunk libs (might not work on Windows)
    #os.environ['LD_LIBRARY_PATH'] = os.path.join(splunk_home, 'lib') + ':' + os.getenv('LD_LIBRARY_PATH', '')
    ld_path = os.path.join(splunk_home, 'lib')
    # This doesn't work because ctypes is not in the Splunk python libraries
    #ctypes.cdll.LoadLibrary(os.path.join(splunk_home, 'lib', 'libxslt.so.1'))

    # We need to set the LD_LIBRARY_PATH to $SPLUNK_HOME/lib,
    # but the LD_LIBRARY_PATH is only read at program start,
    # so set the LD_LIBRARY_PATH and restart this program.
    if not os.environ.get('LD_LIBRARY_PATH'):
        os.environ['LD_LIBRARY_PATH'] = ld_path
    elif not ld_path in os.environ.get('LD_LIBRARY_PATH'):
        os.environ['LD_LIBRARY_PATH'] += ":" + ld_path
    else:
        return  # everything is fine, so don't re-run the program

    # Re-run this program with the new environment variables for Splunk
    # using Splunk's python executable
    python_path = os.path.join(SPLUNK_HOME, 'bin', 'python')
    sys.argv[:0] = [python_path]
    os.execve(python_path, sys.argv, os.environ)