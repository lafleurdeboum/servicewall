#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""

__all__ = ["no_arg_provided", "enable", "disable", "show_logs", "show_realms", "show_services", "show_service", "show_status", "add_service", "del_service"]


import pickle

# Needed to access logging :
from systemd import journal
import select
#import putch
import datetime

# Needed to add/del services :
from servicewall import servicewall
from servicewall import network_helpers

# Needed to show services :
from servicewall import service_helpers

import os


dispatchers = {
    "Network Manager": "/etc/NetworkManager/dispatcher.d/",
    "systemd-networkd": "/etc/networkd-dispatcher/carrier.d/",
}
event_triggerer = "toggler"


firewall = servicewall.ServiceWall()


def print_dict(dictionary, depth=1):
    prefix = "  " * depth
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print("%s=> %s :" % (prefix, key))
            print_dict(value, depth+1)
        else:
            print("%s%s : %s" % (prefix, key, value))


def no_arg_provided(args):
    #parser.print_help()
    raise SystemExit("\n  argument needed !")

def enable(args):
    """Create a link in the network dispatcher pointing to the event triggerer,
    and start the firewall.
    """
    src_dir = firewall.lib_dir
    if not os.path.exists(src_dir):
        # This should never happen ; pip should gracefully put it there.
        raise SystemExit("Could not find %s in %s" %
                (event_triggerer, src_dir))
    witness = False
    for dispatcher, dst_dir in dispatchers.items():
        if not os.path.exists(dst_dir):
            # Keep going with the next dispatcher.
            continue
        if os.path.exists(dst_dir + event_triggerer):
            print("%s dispatcher was already enabled" % dispatcher)
            witness = True
        else:
            print("enabling %s dispatcher" % dispatcher)
            # symlink pointing to src in dst_dir
            os.symlink(src_dir + event_triggerer, dst_dir + event_triggerer)
            witness = True
    if not witness:
        raise SystemExit("Could not link to any network event dispatcher. "
                "You apparently aren't running neither Network Manager nor "
                "systemd-networkd with networkd-dispatcher. You'll need one "
                "of those to run this firewall as it relies on them to fire the "
                "network change events.")

    if firewall.up:
        print("%s was already up" % firewall.identifier)
    else:
        firewall.start()
        print("%s started" % firewall.identifier)

def disable(args):
    """Destroy the link in the network dispatcher pointing to the event triggerer,
    and stop the firewall.
    """

    for dispatcher, target in dispatchers.items():
        # DEBUG This test would fail on a broken link :
        if os.path.exists(target + event_triggerer):
            print("disabling %s dispatcher" % dispatcher)
            os.remove(target + event_triggerer)
        else:
            # Report missing link only if dir is present
            if os.path.exists(target):
                print("%s dispatcher was already disabled" % dispatcher)

    if firewall.up:
        firewall.stop()
        print("firewall stopped")
        print("%s stopped" % firewall.identifier)
    else:
        print("%s was already down" % firewall.identifier)

def status(args):
    if firewall.up:
        if firewall.essid:
            realm_name = firewall.essid
        else:
            realm_name = "no network"
        print("enabled - using profile for %s" % realm_name)
    else:
        print("disabled")

def show_input_chain(args):
    firewall.list_services_in()

def show_realms(args):
    print_dict(firewall.realm_defs)
def show_services(args):
    for service in firewall.service_defs:
        print("%s - %s" % (service, firewall.service_defs[service].description))
def show_service(args):
    service_name = args.service_name
    s = firewall.service_defs[service_name]._asdict()
    s["ports"] = s["ports"]._asdict()
    print_dict(s)
def show_port(args):
    port = args.port_name
    services_list = []
    for service_name, s_tuple in firewall.service_defs.items():
        # port_range is a string containing either a number or a range,
        # as in "80:88", "120"
        for port_range in (*s_tuple.ports.tcp, *s_tuple.ports.udp):
            if port_range.isalnum():
                if port == port_range:
                    services_list.append(service_name)
            else:
                start, end = port_range.split(":")
                if port in range(int(start), int(end)+1):
                    services_list.append(service_name)

    print('services using port %s :' % port)
    for i in services_list:
        print(" - " + i)

def add_service(args):
    service_name = args.service_name
    # Make it local by default :
    firewall.add_service_in(service_name, local=True)
    print("Allowed %s to be served when in realm %s." %
          (service_name, firewall.essid))

def del_service(args):
    service_name = args.service_name
    firewall.del_service_in(service_name)
    print("Removed %s from allowed services on realm %s." %
          (service_name, firewall.essid))

def show_logs(args):
    if "period" in args:
        yielder = log_yielder(int(args.period))
    else:
        yielder = log_yielder()
    now = datetime.datetime.today()

    # log_folder is a dict that contains host adresses as keys,
    # and whose items are dicts that contain port numbers as keys,
    # and whose items are lists of logs, which are dicts.
    #
    # log_folder {
    #             "192.168.1.1": {
    #                             "22": {
    #                                    [log1, log2, ... ] }}}
    #
    # log1: {
    #         "DATE": datetime.timestamp, "SRC": "191.168.1.1", ... }

    log_folder = {}

    for log in yielder:
        if log["SRC"] not in log_folder:
            log_folder[log["SRC"]] = {}
        if "DPT" not in log:
            log["DPT"] = "-1"
        if log["DPT"] not in log_folder[log["SRC"]]:
            log_folder[log["SRC"]][log["DPT"]] = [ log, ]
        else:
            log_folder[log["SRC"]][log["DPT"]].append(log)


    print("Hosts : %s" % ", ".join(ip for ip in log_folder.keys()))
    for src, ports in log_folder.items():
        print("Host %s" % src)
        for dpt, logs in ports.items():
            age = str(now - logs[0]["DATE"]).split(".")[0]
            if dpt == "-1":
                # These packets don't have any destination port.
                # We'll print the first, and any variations on it.
                variations = []
                for log in logs[1:]:
                    for key in log:
                        if key in ("DATE", "ID"):
                            continue
                        if log[key] != logs[0][key]:
                            variations += (key, log[key])
                # Delete "DPT" key as it's not a relevant value :
                del logs[0]["DPT"]
                print("  sent %i unknow packet(s) until %s ago :" %
                        (len(logs), age))
                del logs[0]["DATE"]
                del logs[0]["SRC"]
                for key, value in logs[0].items():
                    print("    %s: %s" % (key, value))
                if variations:
                    print("  variations :")
                    for var in variations:
                        print("    " + var)
            else:
                print("  asked %i times for port %s until %s ago" %
                    (len(logs), dpt, age))

def log_yielder(period=""):
    """get logs we implemented in iptables from journald"""
    reader = journal.Reader()
    reader.log_level(journal.LOG_WARNING)
    reader.add_match(SYSLOG_IDENTIFIER="kernel")
    now = datetime.datetime.today()
    #p = select.poll()
    #p.register(reader, reader.get_events())
    #p.poll()
    reader.seek_tail()
    while True:
        log = reader.get_previous()
        # Quit if there's no message :
        if not "MESSAGE" in log:
            break
        # Quit if log older than period :
        if period:
            age = datetime.datetime.timestamp(now) - datetime.datetime.timestamp(log["__REALTIME_TIMESTAMP"])
            if age > period:
                break
        # Only catch messages sent by iptables log :
        if log["MESSAGE"].startswith(firewall.identifier):
            message_dict = {}
            message = log["MESSAGE"].strip(firewall.identifier + ":").strip()
            message_dict["DATE"] = log["__REALTIME_TIMESTAMP"]
            for item in message.split():
                if item.count("="):
                    key, value = item.split("=")
                    message_dict[key] = value
                else:
                    message_dict[item] = ""
            yield message_dict


