# Magma
#**Mikrotik address-adaptive firewall helper**

*NOTE: This was developed on repositories hosted in-house, as such this is a single commit.*

The Magma firewall helper is designed to complement a PiHole running behind a mikrotik routerboard.
Mikrotik API setup procedure can be found here: https://help.mikrotik.com/docs/display/ROS/REST+API

#**Settings:**

[router_settings]  # These settings can be found here: https://github.com/socialwifi/RouterOS-api
host = <mikrotik-ip-address> \
port = 8729  # API port \
use_ssl = True \
ssl_verify = False \
ssl_verify_hostname = False \
ssl_context = None \
plaintext_login = True \
username = magma \
password = !Complex10-32CharPhraseHere! 

[blast_settings]
block_list = ?magma \
white_list = !magma \
port_redirect_whitelists = [ \
        'MyPortWhitelist', \
    ] \
whitelist_update_time = 15  # Whitelist refresh time. \
update_time = 60  # Blacklists update time. \
hammer_time = 0  # Retry delay. \
special_enable = True  # Enable special feeds (really big ones that we only want to use the latest X number of entries). \
special_limit = 10000  # Number of entries to fetch from the special feeds. \
use_spread = True  # Enable task spreading to minimize resources. \
dry_run = False  # For testing.
  
#**Feeds:**
  
{
  "feeds": [ \
    { \
      "name": "MyFancyWhitelist", \
      "url": "https://example.com/whitelist.txt", \
      "format": "port_whitelist",  # Specifies that this entry will be used as a whitelist. \
      "disabled": false, \
      "type": "list"  # Expect an unsorted list. \
    }, \
    { \
      "name": "SpamHaus Drop", \
      "url": "https://www.spamhaus.org/drop/drop.txt", \
      "format": "cidr",  # Filter CIDR items and add them to the blacklist. \
      "disabled": false, \
      "type": "list"  # Expect an unsorted list. \
    }, \
    { \
      "name": "URLhaus Abuse", \
      "url": "https://urlhaus.abuse.ch/downloads/text/", \
      "format": "special",  # Expect a very large list and apply rules. \
      "disabled": false, \
      "type": "dec_list"  # Expect a list in descending order. \
    }, \
    { \
      "name": "Woody", \
      "url": "https://blacklist.woody.ch", \
      "format": "ip",  # Expect entries in ip address format. \
      "disabled": false, \
      "type": "list"  # Expect unsorted list. \
    }, \
    { \
      "name": "MalwareBytes", \
      "url": "http://hosts-file.net/rss.asp", \
      "format": "rss",  # Expect list in RSS format. \
      "disabled": false, \
      "type": "list"  # Expect unsorted list. \
    } \
]}
  
#**Install Notes:**
  *This package was developed in Python 3.9.6; however, it should work with Python 3.5 <*  \
  Deploy requirements: pip -r install requirements.txt \
  Use example feeds: cp example_feeds.json feeds.json \
  Use example settings: cp example_settings.ini settings.ini \
  Take note to alter the settings file to match your network and routerboard.
                                                                                              
#**Example service (/etc/systemd/system/):**
                
[Unit] \
Description=Magma Blacklists 

[Service] \
Type=simple \
WorkingDirectory=/opt/ \
ExecStart=/bin/sh /bin/magma \
User=magma \
ExecStop= /bin/sleep 20 \
ExecStop= /bin/kill -2 $MAINPID 

[Install] \
WantedBy=multi-user.target

#**Example launch script (/bin/):**
                                                                                              

loc=(YOUR LOCAL MAGMA FOLDER) \                                                                                              
export PATH=$PATH:/opt/venv/bin:/usr/kerberos/sbin:/usr/kerberos/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/us$ alias chdir="cd $loc" \
alias  chdir="cd $loc" \
cd /opt/magma || return \
/usr/bin/python3 -c 'import start'