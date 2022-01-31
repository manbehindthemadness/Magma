# coding=utf-8
"""
This is a neat little utility I call "Magma"

In short this will run as a linux service and is designed to populate a mikrotik router with information from popular
    ip address blacklists. I have no idea how this will impact router performance so I STRONGLY suggest making a backup.
    Connection parameters are stored in settings.ini and lists can be added or removed by editing the feeds.json file.
"""

import threading
from main import Blast
from utils import Term


class Start:
    """
    Simple thread launcher.
    """
    run_state = Term()

    def __init__(self):
        bl = Blast(self)
        self.run = bl.run
        self.run_prwl = bl.run_prwl
        args = (True,)
        self.thread = threading.Thread(target=self.run, args=args)
        self.thread.start()  # Launch the blacklister thread.

        wl_thread = threading.Thread(target=self.run_prwl, args=args)
        wl_thread.start()  # Launch the white lister thread.


Start()
