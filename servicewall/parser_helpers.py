#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""

__all__ = ["no_arg_provided", "enable", "disable", "show_logs", "show_realms", "show_services", "show_service", "show status", "add_service", "del_service"]


import pickle
# Needed to access logging :
from systemd import journal
import select
#import putch
import datetime

# Needed to add/del services :
from servicewall import servicewall
from servicewall import network_helpers

# Needed to parse arguments :
import argparse
#import argcomplete

import os


conf_dir = "/var/lib/servicewall/"
realm_defs_pickle = conf_dir + "realms.p"
service_defs_pickle = conf_dir + "services.p"
definitions_dir = "/etc/gufw/app_profiles"
program_name = "ServiceWall"

with open(realm_defs_pickle, "rb") as fd:
    realm_defs = pickle.load(fd)
with open(service_defs_pickle, "rb") as fd:
    service_defs = pickle.load(fd)

def helper(func, args):
    #wrapper = eval func.__name__
    #wrapper(args)
    func(args)

def print_dict(dictionary):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print("=> %s :" % key)
            print_dict(value)
        else:
            print("%s : %s" % (key, value))


def no_arg_provided(args):
    #parser.print_help()
    raise SystemExit("\n  argument needed !")

def enable(args):
    src = "/etc/NetworkManager/dispatcher.d/toggler"
    dst = "/usr/lib/servicewall/toggler"
    if os.path.exists(src):
        print("Already enabled")
    else:
        os.symlink(dst, src)
    firewall = servicewall.ServiceWall()
    if not firewall.up:
        firewall = servicewall.ServiceWall()
        firewall.start()
        print("Firewall started")

def disable(args):
    target = "/etc/NetworkManager/dispatcher.d/toggler"
    # DEBUG This test would fail on a broken link :
    if os.path.exists(target):
        os.remove(target)
    else:
        print("Already disabled")
    firewall = servicewall.ServiceWall()
    if firewall.up:
        firewall.stop()
        print("Firewall stopped")


def show_status(args):
    firewall = servicewall.ServiceWall()
    firewall.list_services_in()

def show_realms(args):
    print_dict(realm_defs)
def show_services(args):
    for service in service_defs:
        print("%s - %s" % (service, service_defs[service]["description"]))
def show_service(args):
    #service_name = args.service_name
    # The calling parser has nargs="*", so args.service_name is a list
    service_name = " ".join(args.service_name)
    # Do our own validity testing
    if service_name not in service_defs:
        #parser_show_service.print_usage()
        raise SystemExit('service "%s" not found. ')
    print_dict(service_defs[service_name])

def add_service(args):
    service_name = args.service_name
    print(service_name, str(len(service_name)))
    # Do our own validity testing
    if service_name not in service_defs:
        raise SystemExit('service "%s" not found. ')
    essid = network_helpers.get_essid()
    if service_name in realm_defs[essid]:
        raise SystemExit("Service %s already in realm %s's definition" %
                (service_name, essid))
    realm_defs[essid][service_name] = False
    with open(realm_defs_pickle, "wb") as fd:
        pickle.dump(realm_defs, fd)
    firewall = servicewall.ServiceWall()
    firewall.add_service_in(service_name, local=False)
    print("Allowed %s to be served when in realm %s." % (service_name, essid))

def del_service(args):
    service_name = args.service_name
    # Do our own validity testing
    if service_name not in service_defs:
        raise KeyError('service "%s" not found. ')
    essid = network_helpers.get_essid()
    if service_name in realm_defs[essid]:
        del realm_defs[essid][service_name]
    else:
        raise KeyError('service "%s" not allowed in realm %s anyway.'
                % (service_name, essid))
    with open(realm_defs_pickle, "wb") as fd:
        pickle.dump(realm_defs, fd)
    firewall = servicewall.ServiceWall()
    firewall.del_service_in(service_name)
    print("Removed %s from allowed services on realm %s." % (service_name, essid))

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
        if log["MESSAGE"].startswith(program_name):
            message_dict = {}
            message = log["MESSAGE"].strip(program_name + ":").strip()
            message_dict["DATE"] = log["__REALTIME_TIMESTAMP"]
            for item in message.split():
                if item.count("="):
                    key, value = item.split("=")
                    message_dict[key] = value
                else:
                    message_dict[item] = ""
            yield message_dict


