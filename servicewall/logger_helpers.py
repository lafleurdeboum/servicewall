#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""braise - a dynamic firewall

"""


from systemd import journal
import datetime
#import select
#import putch
from servicewall import servicewall


debug = False
identifier = "ServiceWall"

firewall = servicewall.ServiceWall()

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

def log_yielder(period=""):
    """get logs we implemented in iptables from journald"""
    # Equivalent to :
    #   journalctl --identifier kernel -p warning | grep ServiceWall
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
        if log["MESSAGE"].startswith(identifier):
            message_dict = {}
            message = log["MESSAGE"].strip(identifier + ":").strip()
            message_dict["DATE"] = log["__REALTIME_TIMESTAMP"]
            for item in message.split():
                if item.count("="):
                    key, value = item.split("=")
                    message_dict[key] = value
                else:
                    message_dict[item] = ""
            yield message_dict


