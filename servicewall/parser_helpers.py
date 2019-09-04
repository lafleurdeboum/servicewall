#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""

__all__ = ["no_arg_provided", "enable", "disable", "reload", "show", "show_logs", "show_realm", "show_realms", "show_services", "show_service", "show_status", "allow_service", "disallow_service"]


import os
import pickle
import json
from datetime import datetime
#import select
#import putch
import socket
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

def allow_service(args):
    service_name = args.service_name
    # Make it local by default :
    firewall.add_service_in(service_name, local=True)

def allow_service_globally(args):
    service_name = args.service_name
    firewall.add_service_in(service_name, local=False)

def disallow_service(args):
    service_name = args.service_name
    firewall.del_service_in(service_name)

def show_input_chain(args):
    firewall.list_services_in()

def show_realm(args):
    print('Current realm is "%s". Allowed services (true means locally allowed) :'
                % firewall.realm_id)
    prettyprint(firewall.realm_defs[firewall.realm_id])
def show_realms(args):
    #print_dict(firewall.realm_defs)
    prettyprint(firewall.realm_defs)

def show_service(args):
    s = firewall.service_defs[args.service_name]._asdict()
    #s["ports"] = s["ports"]._asdict()
    prettyprint(s)
def show_services(args):
    for service in firewall.service_defs:
        print("%s - %s" % (service, firewall.service_defs[service].description))

def show_port(args):
    port = args.port_name
    services_list = firewall.list_services_by_port(port)
    if services_list:
        if len(services_list) == 1:
            print("service using port %s : %s" % (port, services_list[0]))
        else:
            print('services using port %s :' % port)
            #[ print("  - %s" % i) for i in services_list ]
            prettyprint(services_list)
    else:
        print("port %s unknown." % port)

def show_logs(args):
    if "period" in args:
        yielder = firewall.yield_logs(period=args.period)
    else:
        yielder = firewall.yield_logs()
    if args.withnames:
        withnames = True
    else:
        withnames = False
    if "limit" in args:
        limit = int(args.limit)
        i = 0
    else:
        limit = None

    log_folder = {}
    now = datetime.today()
    starred = False

    for log in yielder:
        if limit:
            i += 1
            if i > limit:
                break

        if withnames:
            # If we have a hostname, output it - shortened if longer than 19 :
            try:
                hostname = socket.gethostbyaddr(log['SRC'])[0]
                if len(hostname) > 22:
                    log['SRC'] = '%s ...%s' % (log['SRC'], hostname[-17:])
                else:
                    log['SRC'] = '%s %s' % (log['SRC'], hostname)
            except socket.herror:
                pass

        # If we have a source port, try to name its service :
        if log['SPT']:
            services_list = firewall.list_services_by_port(log['SPT'])
            if services_list:
                if len(services_list) > 1:
                    log['PROTO'] = '%s*' % services_list[0]
                    starred = log['SPT']
                else:
                    log['PROTO'] = '%s' % services_list[0]

        age = now - log['LOG_DATE']
        if age.days:
            age = str(age).split(',')[0]
        else:
            age = str(age).split('.')[0]

        print('%-37s %-16s %-10s %-5s %8s' % (
            log['SRC'],
            log['DST'],
            log['PROTO'],
            log['SPT'],
            age
        ))
    if starred:
        print('* for full list see e.g. "braise show port %s"' % starred)

