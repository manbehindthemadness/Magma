# coding=utf-8
"""
Here is where we will store arbitrary code used in the rest of the application.
"""
import configparser
import json
import logging
import random
import re
import signal
import socket
import time
import uuid
import dns.resolver
from pathlib import Path
from subprocess import Popen, PIPE

import netaddr
import requests
from OpenSSL import crypto

logging.getLogger().setLevel(logging.INFO)


def log(*args):
    """
    Really simple-ass logger.
    """
    message = str()
    for arg in args:
        message += str(arg) + ' '
    logging.info(message)


def system_command(params):
    """
    Use this to execute a system level command.

    NOTE: Use with caution.
    :param params: List of commands and args to execute.
    :type params: list
    :return: stout.
    :rtype: PIPE
    """
    process = Popen(params, stdout=PIPE)
    output, _error = process.communicate()
    output = output.decode("utf8")
    return output


class Term:
    """
    This watches for a service termination signal
    """
    term = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.signal)
        signal.signal(signal.SIGTERM, self.signal)

    # noinspection PyUnusedLocal
    def signal(self, *args):
        """
        Signal callback.
        """
        self.term = True


class Dummy:
    """
    Aptly named.
    """
    term = False


run_state = Term()


class Config:
    """
    This will read and evaluate our configurations.
    """

    def __init__(self, section: str):
        self.file = 'settings.ini'
        self.config = configparser.ConfigParser()
        self.config.read(self.file)
        self.rconf = self.config[section]

    def read(self, key: str) -> eval:
        """
        This will read and evaluate a configured setting
        """
        answer = self.rconf[key]
        if answer.isnumeric() or answer in ['True', 'False', 'None']:
            return eval(answer)
        else:
            return answer

    @staticmethod
    def cert_wiz():
        """
        This creates a default set of self-signed x509 certificates
        """

        KEY_FILE = Path('ss.key')
        CERT_FILE = Path('ss.crt')
        if not KEY_FILE.is_file() or not CERT_FILE.is_file():
            log('Creating self signed SSL certificates')
            log(
                'NOTE if using more than one cv application on the same system \n the passphrase must be copied inbetween settings.ini files!')
            host, ip = get_netinfo()
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 4096)
            cert = crypto.X509()
            cert.get_subject().CN = host
            suffix = str()
            if '.' not in host:
                suffix += '.local'
            cert.get_subject().emailAddress = 'admin@' + host + suffix
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
            sn = random.randint(10000, 99999)
            cert.set_serial_number(sn)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            # noinspection PyTypeChecker
            cert.sign(key, 'sha512')
            passphrase = str(uuid.uuid4())
            with open(CERT_FILE, "wt") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
            with open(KEY_FILE, "wt") as f:
                f.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=passphrase.encode()).decode("utf-8"))
            log('creating keyfile:', passphrase)


config = Config('blast_settings').read


def spread(last_load: [int, float] = 50000) -> float:
    """
    This helps us spread out the load across the update cycle.
    """
    if config('use_spread'):
        cycle = config('update_time') * 60
        hammer = config('hammer_time') * last_load  # I couldn't resist...
        ops_sec = last_load / (cycle + hammer)
        sec_ops = 1 / ops_sec
        pause_count = 6  # The number of times we call this in the logic. (2x2 in the process and 2 in the main loop)
        ops = round(sec_ops / pause_count, 4)
        log('MAGMA: adjusting seconds per operation to:', ops)
        return ops
    else:
        return 0.0


throttle = spread()


def json_read(file: str) -> dict:
    """
    This reads the contents of a JSON file.

    :param file: Path and filename to read.
    :type file: str
    :return: JSON data.
    :rtype: dict
    """
    with open(file) as f:
        return json.load(f)


def url_read(url: str) -> [requests, None]:
    """
    This reads a file from the url value supplied.

    :param url: URL of file to read.
    :type url: str
    :return: File contents.
    :rtype: response, NoneType
    """
    if url:
        try:
            try:
                return requests.get(url)
            except requests.exceptions.MissingSchema:
                try:
                    return requests.get('https://' + url)
                except requests.exceptions.ConnectionError:
                    # noinspection HttpUrlsUsage
                    return requests.get('http://' + url)
        except requests.exceptions.ConnectionError:
            print('unable to contact:', url)
            return None
    else:
        return None


pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
search = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')  # noqa


def filter_address(address: str) -> list:
    """
    This takes unfiltered string data and extracts a properly formatted IP address.
    """
    result = list()

    rough_address = pattern.findall(address)
    if rough_address:  # Check to see if we have an address.
        for address in rough_address:  # Walk the results in case there is more than one.
            try:
                clean_address = (netaddr.IPAddress(address, flags=netaddr.ZEROFILL).ipv4())  # format the ip address.
                result.append(str(clean_address))  # Add address to results array.
            except netaddr.core.AddrFormatError:
                pass

    return result


def get_netinfo() -> tuple:
    """
    This returns a tuple (hostname, ipv4 addresses)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return socket.gethostname(), ip


def get_addresses() -> dict:
    """
    This collects ip blacklist resource data and prepares it for retrieval.
    """
    jobs = json_read('feeds.json')
    return jobs['feeds']


def get_latest(content: list, count: int = 1000, rev: bool = True) -> list:
    """
    This will gather the latest 'count' items from a list
    """
    if rev:
        content.reverse()
    return content[0:count]


def process_addresses(job_type: str, rollover: [list, None] = None, term: Term = Dummy()) -> tuple:
    """
    This pulls blacklist information from an array of jobs.
    """
    global throttle

    jobs = get_addresses()

    results = list()
    if rollover:
        results = rollover

    for job in jobs:  # Walk job list.
        time.sleep(throttle)
        if term.term:
            break
        if job['format'] == job_type and not job['disabled']:  # Confirm we are operating on the correct resources.
            contents = url_read(job['url'])  # Fetch remote data.
            if 'list' in job['type'] and contents:  # Confirm we are processing with the right format
                bulk = contents.text.splitlines()
                log('MAGMA: collected', len(bulk), 'from', job['name'], ', processing...')
                rev = False
                latest_only = False  # This will handle the collection of only the latest entries from the job.
                if job['type'] == 'asc_list':
                    rev = True
                    latest_only = True
                if job['type'] == 'dec_list':
                    latest_only = True
                if latest_only:
                    bulk = get_latest(content=bulk, count=config('special_limit'), rev=rev)
                for item in bulk:  # Walk through data.
                    time.sleep(throttle)
                    if term.term:
                        break
                    entries = filter_address(item)  # Filter out ip addresses.
                    if entries:  # See if we have data.
                        for address in entries:  # Walk data.
                            if term.term:
                                break
                            if address not in results:
                                results.append(address)  # Construct results.
    if rollover:
        throttle = spread(len(results))  # Adjust process spread for the next cycle.
    return results, throttle


def resolve_domains() -> list:
    """
    This will resolve the domains in our feed list and ensure they don't blacklist each other.
    """
    results = list()
    jobs = get_addresses()
    for job in jobs:
        try:
            source = dns.resolver.resolve(job['url'], 'A')
            for address in source:
                results.append(address.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
    return results
