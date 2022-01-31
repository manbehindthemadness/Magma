# coding=utf-8
"""
This is a neat little utility I call "Magma"

In short this will run as a linux service and is designed to populate a mikrotik router with information from popular
    ip address blacklists. I have no idea how this will impact router performance so I STRONGLY suggest making a backup.
    Connection parameters are stored in settings.ini and lists can be added or removed by editing the feeds.json file.
"""
import time
import threading  # noqa
from mikrotikapi import Client, exceptions
from utils import log, Config, process_addresses, resolve_domains


class Blast:
    """
    This is our monster ip blacklister with a cool-ass name.

    TODO: We need to do some experimentation and figure out how to handle connection outages.
    """
    def __init__(self, parent):
        self.parent = parent
        self.config = Config('blast_settings').read
        self.client = Client()
        self.api = None

        self.throttle = 0

        self.router_addresses = None
        self.router_wl_addresses = None
        self.blacklist_addresses = None
        self.addr_lists = None
        self.router_ids = None
        self.router_wl_ids = None
        self.additions = None
        self.removals = None

        self.update_running = False  # Job lockers.
        self.whitelist_running = False
        self.api_connected = False

        self.dummy = None

    def connect_api(self):
        """
        This will get us connected to the router.
        """
        self.client.connect()
        self.api = self.client.api
        self.api_connected = self.client.connected
        return self

    def get_blacklist(self, specials: bool = False):
        """
        This will gather the remote black list information.
        :return:
        """
        self.blacklist_addresses, self.throttle = process_addresses('ip', term=self.parent.run_state)
        if specials:  # Collects the latest entries from the "really big" lists.
            log('MAGMA: acquiring specials')
            self.blacklist_addresses, self.throttle = process_addresses(
                job_type='special',
                rollover=self.blacklist_addresses,
                term=self.parent.run_state
            )
        return self

    def format_addresses(self, address_list: list) -> tuple:
        """
        This gets the adresses and the rule id from the output of the router.
        """
        ids = list()
        addresses = list()
        for address in address_list:
            time.sleep(self.throttle)
            ids.append(address['id'])
            addresses.append(address['address'])
        return ids, addresses

    def get_router_lists(self, client_only: bool = False):
        """
        This will gather all the ipaddresses from the router.
        """
        self.addr_lists = self.api.get_resource('/ip/firewall/address-list')
        if not client_only:
            raw_address_list = self.addr_lists.get(list=self.config('block_list'))
            raw_wl_address_list = self.addr_lists.get(list=self.config('white_list'))
            self.router_ids, self.router_addresses = self.format_addresses(raw_address_list)
            self.router_wl_ids, self.router_wl_addresses = self.format_addresses(raw_wl_address_list)
            sources = resolve_domains()
            for source in sources:
                if source not in self.router_wl_addresses:
                    self.router_wl_addresses.append(source)
        return self

    def add_address(self, address: str, address_list: str, timeout: str = None, comment: str = None, quiet: bool = False):
        """
        Adds an address to the specified list.
        """
        kwargs = {
            'address': address,
            'list': address_list
        }
        if timeout:
            kwargs.update({'timeout': timeout})
        if comment:
            kwargs.update({'comment': comment})
        try:
            self.addr_lists.add(**kwargs)
        except exceptions as err:
            if not quiet:
                log('MAGMA: add address error', err)
        return self

    def remove_address(self, address_id: str):
        """
        This will remove an address from the specified list.
        """
        try:
            self.addr_lists.remove(id=address_id)
        except exceptions as err:
            log('MAGMA: remove address error', err)

    def update(self):
        """
        Here we compare the remote address list with the one in the router and update it accordingly.
        """
        self.update_running = True
        if not self.api_connected:
            self.connect_api()
        self.get_blacklist(self.config('special_enable'))
        log('MAGMA: Blacklist acquired:', len(self.blacklist_addresses), 'addresses')
        self.get_router_lists()
        log('MAGMA: router address list acquired')
        # Find removals.
        log('MAGMA: processing removals')
        self.removals = list()
        for idx, address in enumerate(self.router_addresses):
            time.sleep(self.throttle)
            if self.parent.run_state.term:
                break
            if address not in self.blacklist_addresses or address in self.router_wl_addresses:
                self.removals.append(
                    self.router_ids[idx]
                )
        log('MAGMA: processing additions')
        # Find additions.
        self.additions = list()
        for address in self.blacklist_addresses:
            time.sleep(self.throttle)
            if self.parent.run_state.term:
                break
            if address not in self.router_addresses:
                if address not in self.router_wl_addresses:
                    self.additions.append(address)
        log('MAGMA: address removals', len(self.removals))
        log('MAGMA: address additions', len(self.additions))
        log('MAGMA: blocking', len(self.router_addresses), 'addresses')
        log('MAGMA: processed', len(self.blacklist_addresses), 'items')
        log('MAGMA: updating router to reflect results')
        # Update router with new information.
        if self.config('dry_run'):
            log('MAGMA: system dry run enabled, skipping router config')
        else:
            hammer_time = self.config('hammer_time')
            for address_id in self.removals:
                if self.parent.run_state.term:
                    break
                self.remove_address(address_id)
                time.sleep(hammer_time + self.throttle)
            for address in self.additions:
                if self.parent.run_state.term:
                    break
                time.sleep(hammer_time + self.throttle)
                self.add_address(address, self.config('block_list'))
        if not self.whitelist_running:
            self.client.disconnect()
            self.api_connected = self.client.connected
        self.update_running = False
        return self

    def port_redirect_whitelister(self):
        """
        This allows us to lookup port redirect whitelisted addresses from a domain and add them into the
            proper address_list.
        """
        self.whitelist_running = True
        if not self.api_connected:
            self.connect_api()
        self.get_router_lists(client_only=True)
        whitelists = eval(self.config('port_redirect_whitelists'))
        addresses, self.dummy = process_addresses('port_whitelist', term=self.parent.run_state)
        for address in addresses:
            for whitelist in whitelists:
                self.add_address(address, whitelist, timeout='14m', comment='magma whitelister', quiet=True)
                log('MAGMA: whitelisting', address, 'for list', whitelist)
        log('MAGMA: port whitelisting complete')
        if not self.update_running:
            self.client.disconnect()
            self.api_connected = self.client.connected
        self.whitelist_running = False

    def run_prwl(self, bypass: bool = False):
        """
        This will run our port redirect whitelist loop.
        """
        if __name__ == '__main__' or bypass:
            log('MAGMA: redirect whitelist starting')
            cycle = self.config('whitelist_update_time') * 60
            while not self.parent.run_state.term:
                self.port_redirect_whitelister()
                duration = cycle
                while duration and not self.parent.run_state.term:
                    time.sleep(1)
                    duration -= 1
            log('MAGMA: port whitelister exiting')

    def run(self, bypass: bool = False):
        """
        This is our main-loop.
        """
        if __name__ == '__main__' or bypass:
            cycle = self.config('update_time') * 60
            while not self.parent.run_state.term:
                duration = cycle
                log('MAGMA: starting blacklist update')
                self.update()
                log('MAGMA: blacklist list update complete')
                if not self.config('use_spread'):  # See if we are spreading the task or going in cycles.
                    while duration and not self.parent.run_state.term:
                        time.sleep(1)
                        duration -= 1
                else:
                    time.sleep(5)
                    log('MAGMA: resetting spread cycle')
                    time.sleep(5)
