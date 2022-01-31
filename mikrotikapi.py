# coding=utf-8

"""
Here we will use config parser and the mikrotik api to create a basic client that can add or remove from the address
    list we have configured to hold the blacklist.
"""
import time
import routeros_api
from routeros_api.exceptions import *
from utils import Config, log

exceptions = (
    RouterOsApiError,
    RouterOsApiParsingError,
    RouterOsApiCommunicationError,
    RouterOsApiConnectionError,
    RouterOsApiConnectionClosedError,
    RouterOsApiError,
    RouterOsApiFatalCommunicationError,
    FatalRouterOsApiError
)


class Client:
    """
    This will provide us with read and write operations to the mikrotik api.
    """

    def __init__(self):
        self.conf = Config('router_settings').read
        self.api = None
        self.connection = None
        self.connected = False

    def connect(self):
        """
        This fires up a connection to the router
        """
        try:
            self.connection = routeros_api.RouterOsApiPool(
                self.conf('host'),
                username=self.conf('username'),
                password=self.conf('password'),
                plaintext_login=self.conf('plaintext_login'),
                use_ssl=self.conf('use_ssl'),
                ssl_verify=self.conf('ssl_verify'),
                ssl_verify_hostname=self.conf('ssl_verify_hostname')
            )
            self.api = self.connection.get_api()
        except RouterOsApiConnectionError:
            log('MAGMA: unable to contact router API, retrying')
            time.sleep(5)
            self.connect()
        self.connected = True
        return self

    def disconnect(self):
        """
        Terminates the connection
        """
        self.connection.disconnect()
        self.connected = False
        return self
