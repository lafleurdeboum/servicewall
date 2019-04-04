#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""

__all__ = ["no_arg_provided", "enable", "disable", "reload", "show_logs", "show_realms", "show_services", "show_service", "show_status", "allow_service", "disallow_service"]


import os
import pickle
import json
from datetime import datetime
#import select
#import putch
import servicewall


debug = False
firewall = servicewall.ServiceWall()


def prettyprint(obj):
    print(json.dumps(obj, indent=2))

def print_dict(dictionary, depth=1):
    prefix = "  " * depth
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print("%s=> %s :" % (prefix, key))
            print_dict(value, depth+1)
        else:
            print("%s%s : %s" % (prefix, key, value))


def no_arg_provided(args):
    parser.print_help()
    #raise SystemExit("\n  argument needed !")

def enable(args):
    firewall.enable()

def disable(args):
    firewall.disable()

def reload(args):
    firewall.reload()

def status(args):
    if firewall.config["enabled"]:
        if firewall.realm_id:
            realm_name = firewall.realm_id
        else:
            realm_name = "no network"
        print("enabled - using profile for realm %s" % realm_name)
    else:
        print("disabled")

def show_input_chain(args):
    firewall.list_services_in()

def show_realms(args):
    #print_dict(firewall.realm_defs)
    prettyprint(firewall.realm_defs)
def show_services(args):
    for service in firewall.service_defs:
        print("%s - %s" % (service, firewall.service_defs[service].description))
def show_service(args):
    s = firewall.service_defs[args.service_name]._asdict()
    #s["ports"] = s["ports"]._asdict()
    prettyprint(s)
def show_port(args):
    port = args.port_name
    services_list = firewall.list_services_by_port(port)
    if services_list:
        if len(services_list) == 1:
            print("service using port %s : %s" % (port, services_list[0]))
        else:
            print('services using port %s :' % port)
            prettyprint(services_list)
            #[ print("  - %s" % i) for i in services_list ]
    else:
        print("port %s unknown." % port)

def allow_service(args):
    service_name = args.service_name
    # Make it local by default :
    firewall.add_service_in(service_name, local=True)

def disallow_service(args):
    service_name = args.service_name
    firewall.del_service_in(service_name)


def show_logs(args):
    if "period" in args:
        yielder = firewall.log_yielder(int(args.period))
    else:
        yielder = firewall.log_yielder()
    now = datetime.today()

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
            if dpt != "-1":     # Then dpt is a valid port.
                print("  asked %i times for port %s until %s ago" %
                    (len(logs), dpt, age))
                services_list = firewall.list_services_by_port(dpt)
                if services_list:
                    if len(services_list) == 1:
                        print('    (should be service %s)' % services_list[0])
                    else:
                        print('    (could be any of services %s)' % services_list)
            elif debug:         # Then dpt is undefined.
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


