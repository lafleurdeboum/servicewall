#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""

__all__ = ["no_arg_provided", "enable", "disable", "reload", "show_logs", "show_realms", "show_services", "show_service", "show_status", "add_service", "del_service"]


import os
import pickle
import json
from servicewall import servicewall


# This will fail if not root :
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
    #parser.print_help()
    raise SystemExit("\n  argument needed !")

def enable(args):
    firewall.enable()

def disable(args):
    firewall.disable()

def reload(args):
    firewall.reload()

def status(args):
    if firewall.config["enabled"]:
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

def add_service(args):
    service_name = args.service_name
    # Make it local by default :
    firewall.add_service_in(service_name, local=True)
    firewall.save_rules()

def del_service(args):
    service_name = args.service_name
    firewall.del_service_in(service_name)
    firewall.save_rules()

