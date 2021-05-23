#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Helper functions for ServiceWall cmdline agent.
"""

__all__ = [ "no_arg_provided", "enable", "disable", "start", "stop", "reload",
            "show_logs", "show_realm", "show_realms", "show_services",
            "show_service", "status", "allow_service", "disallow_service" ]


import json
from datetime import datetime
#import select
#import putch
import socket
import servicewall


DEBUG = False
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


def print_service(port):
    services_list = firewall.list_services_by_port(port)
    if len(services_list) > 1:
        return '%s*' % services_list[0]
    elif len(services_list) == 1:
        return '%s' % services_list[0]
    return None


def no_arg_provided(args):
    parser.print_help()
    #raise SystemExit("\n  argument needed !")


def enable(args):
    firewall.enable()


def disable(args):
    firewall.disable()


def start(args):
    firewall.start()


def stop(args):
    firewall.stop()


def reload(args):
    firewall.reload()


def status(args):
    if firewall.is_enabled():
        print("ServiceWall is enabled")
    else:
        print("ServiceWall is disabled")
    if firewall.up:
        if firewall.realm_id:
            realm_name = firewall.realm_id
        else:
            realm_name = "no network"
        print("and started - using profile for realm %s" % realm_name)
    else:
        print("and stopped")


def allow_service(args):
    if args.globally:
        scope = "global"
    elif args.docker:
        scope = "docker"
    else:
        scope = "local"
    if args.in_default_profile:
        realm = "ServiceWall:default"
    else:
        realm = None
    # Make it local by default :
    firewall.allow_service(args.service_name, scope=scope, realm=realm)


def disallow_service(args):
    service_name = args.service_name
    if args.in_default_profile:
        realm = "ServiceWall:default"
    else:
        realm = None
    firewall.disallow_service(service_name, realm=realm)


def show_table(args):
    print('You are using realm profile : %s' %
          (firewall.realm_id or "ServiceWall:default"))
    print('=> Input rules <=           : policy %6s' %
          firewall.input_chain.get_policy().name)
    for rule in firewall.list_rules(firewall.input_chain):
        print(rule)
    print('=> Forward rules <=         : policy %6s' %
          firewall.forward_chain.get_policy().name)
    for rule in firewall.list_rules(firewall.forward_chain):
        print(rule)
    print("=> Output rules <=          : policy %6s" %
          firewall.output_chain.get_policy().name)


def show_realm(args):
    if firewall.realm_id:
        print('This machine is connected to ESSID "%s".' % firewall.realm_id)
    else:
        print('This machine is not connected.')
    #prettyprint(firewall.realm_defs[firewall.realm_id])


def show_realms(args):
    #print_dict(firewall.realm_defs)
    prettyprint(firewall.realm_defs)


def show_service(args):
    s = firewall.service_defs[args.service_name]._asdict()
    s["ports"] = s["ports"]._asdict()
    prettyprint(s)


def show_services(args):
    for service in firewall.service_defs:
        print("%s - %s"
              % (service, firewall.service_defs[service].description))


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
    if "number" in args:
        limit = int(args.number)
        i = 0
    else:
        limit = None

    now = datetime.today()

    for log in yielder:
        if limit:
            i += 1
            if i > limit:
                break

        if "with_hostnames" in args:
            # If we have a hostname, output it - shortened if longer than :
            try:
                hostname = socket.gethostbyaddr(log['SRC'])[0]
                if len(hostname) > 20:
                    log['SRC'] = '%s ..%s' % (log['SRC'], hostname[-17:])
                else:
                    log['SRC'] = '%s %s' % (log['SRC'], hostname)
            except socket.herror:
                pass

        # If we have ports, try to name the associated service :
        if log['DPT'] or log['SPT']:
            servicename = print_service(log['DPT'])
            if servicename:
                service = '> %s (%s/%s)' % (
                    servicename,
                    log['PROTO'],
                    log['DPT']
                )
            else:
                servicename = print_service(log['SPT'])
                if servicename:
                    service = '>>%s (%s/%s)' % (
                        servicename,
                        log['PROTO'],
                        log['SPT']
                    )
                else:
                    # We have no port, display protocol :
                    service = '%5s>%5s %-5s' % (
                        log['SPT'],
                        log['DPT'],
                        log['PROTO']
                    )
        else:
            # We have no port, display protocol :
            service = 'layer3: %s' % log['PROTO']

        age = now - log['LOG_DATE']
        if age.days:
            age = str(age).split(',')[0]
        else:
            age = str(age).split('.')[0]

        print('%-36s %-16s %17s %-8s' % (
            log['SRC'],
            log['DST'],
            service,
            age
        ))

