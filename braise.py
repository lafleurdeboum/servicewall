#!/usr/bin/env python
"""adaptative firewall

braise.py creates iptables rules to allow the services you ask it to
on the current subnetwork.
"""

__version__ = "0.1"
__author__ = "la Fleur"


import pickle
from os import environ
from iptc import Rule, Match, Chain, Table

from helpers import scan_service_definitions

conf_dir = "var/lib/braise/"
state_pickle = conf_dir + "state.p"
realm_pickle = conf_dir + "realm.p"
realm_definitions_pickle = conf_dir + "realms.p"
services_pickle = conf_dir + "services.p"
definitions_dir = "/etc/gufw/app_profiles"

def update_services(pickle_file):
    """Dumps a dict of network service definitions to pickle_file."""
    services = scan_service_definitions(definitions_dir)
    with open(services_pickle, "wb") as pickle_fd:
        pickle.dump(pickle_fd, services)


def get_local_subnet():
    """Returns the local subnet iface is connected to."""
    try:
        local_realm = environ["IP4_ROUTE_0"].split("/")[0]
    except KeyError:
        raise SystemExit(
                "No env. Was the script really started by NetworkManager ?")
    # If the first functions, then these should as well.
    local_realm += "/" + environ["DHCP4_SUBNET_MASK"]
    essid = environ["CONNECTION_ID"]
    #uuid = environ["CONNECTION_UUID"]
    return (local_realm, essid)


def add_iptables_rule(title, chain, target, realm="", port="", proto=""):
    """Creates an iptable rule and adds it to chain."""
    rule = Rule()
    #rule.in_interface = "wlan0"
    if realm:
        rule.src = realm

    # _Sometimes_ mandatory DEBUG.
    if proto:
        rule.protocol = proto

    # Add a match on destination port.
    if port:
        if proto:
            proto_match = Match(rule, proto)
            # We stock ports as ints, but iptc wants strings
            proto_match.dport = str(port)
            rule.add_match(proto_match)
        else:
            raise SystemExit("need to set a protocol for this match")

    # Add the title as a comment.
    comment_match = Match(rule, "comment")
    comment_match.comment = title
    rule.add_match(comment_match)

    rule.create_target(target)

    rule.final_check()

    # Insert into chain.
    index = len(chain.rules)
    chain.insert_rule(rule)
    # len(chain.rules) should have been incremented.
    if index == len(chain.rules):
        raise SystemExit("rule was not inserted. Go get the problem.")

def del_iptables_rule(title, chain, target, realm="", port="", proto=""):
    pass


def start_firewall(realm, essid):
    """launches a firewall for realm represented by essid"""
    # TODO We should start base from anywhere anyhow, and then look for
    # the realm
    special_definitions = {
            "base" : [
                ("DHCP", "local"),
                ("ssh", "global"),
            ]
    }
    with open(realm_definitions_pickle, "rb") as fd:
        realm_definitions = pickle.load(fd)


    # Is netbios the same thing as Samba ? UFW says 445 is samba,
    # and netbios is 137, 138 and 139. iptables says 445 is microsoft-ds,
    # 137 is netbios-ns, 138 is netbios-dgm and 139 is netbios-ssn
    # Check mDNS :
    # -A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT
    # Check UPnP :
    # -A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

    # Check that we have a valid dhcp rule - DEBUG why does NM get a lease
    # when the firewall is up ?
    # -A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT
    # And perhaps icmp :
    # -A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
    # -A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT
    # -A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
    # -A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
    # -A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

    # And then logging, and then rate limiting
    # And allow all on loopback - apparently OK when we DROP INPUT or OUTPUT :
    # -A ufw-before-input -i lo -j ACCEPT
    # -A ufw-before-output -o lo -j ACCEPT
    # there's also the skype problem (see /etc/gufw/app_profiles)

    print("IP4 address : $s" % environ)
    print("realm : %s essid : %s" % (realm, essid))

    filter_table = Table(Table.FILTER)
    filter_table.autocommit = False
    input_chain = Chain(filter_table, "INPUT")
    input_chain.set_policy("DROP")

    with open(services_pickle, "rb") as pickle_fd:
        service_definitions = pickle.load(pickle_fd)

        try:
            local_subnet_definition = realm_definitions[essid]
            print("found a realm definition for %s" % essid)
        except KeyError:
            local_subnet_definition = special_definitions['base']
            print("found no realm definition for %s, using base protocols"
                    % essid)

        for service_name, service_realm in local_subnet_definition:
            try:
                service = service_definitions[service_name]
            except KeyError:
                print(
                        "WARNING - Could not find service %s" % service_name)
                continue
            if service_realm == "local":
                service_realm = realm
            else:
                service_realm = ""
            for port_description in service["ports"]:
                for port, proto in [port_description]:
                    print("%s %s : inserting rule for %s : %i/%s"
                            % (input_chain.table.name, input_chain.name,
                               service_name, port, proto))
                    if proto:
                        add_iptables_rule(service["title"], input_chain,
                                "ACCEPT", service_realm, port, proto)
                    else:
                        # We'll presume we want both tcp and udp, and
                        # nothing else.
                        add_iptables_rule(service["title"], input_chain,
                                "ACCEPT", service_realm, port, "tcp")
                        add_iptables_rule(service["title"], input_chain,
                                "ACCEPT", service_realm, port, "udp")

        # First rule should be to allow related, established connections
        related_rule = Rule()
        related_match = related_rule.create_match("conntrack")
        related_match.set_parameter("ctstate", "RELATED,ESTABLISHED")
        comment_match = related_rule.create_match("comment")
        comment_match.comment = "related"
        related_rule.create_target("ACCEPT")
        input_chain.insert_rule(related_rule)

        filter_table.commit()
        with open(state_pickle, "wb") as state_fd:
            pickle.dump(local_subnet_definition, state_fd)
        with open(realm_pickle, "wb") as realm_fd:
            pickle.dump(realm, realm_fd)
        # If commitment fails, it would throw an error, so we wouldn't
        # get here.
        print("table commited")


def stop_firewall(realm, started_services, services):
    print("removing firwall iptables rules")
    table = Table(Table.FILTER)
    table.autocommit = False
    chain = Chain(table, "INPUT")

    # Need to take the "RELATED,ESTABLISHED" rule away
    #started_services.append(("related", "None"))
    for rule in chain.rules:
        try:
            if rule.matches[1].comment == "related":
                chain.delete_rule(rule)
                break
        except IndexError:
            continue

    for service, realm in started_services:
        for rule in chain.rules:
            # match[0] is the port, match[1] is the comment. Else it's not us.
            try:
                match = rule.matches[1]
            except IndexError:
                continue
            try:
                service_name = match.parameters["comment"]
            except KeyError:
                continue
            if services[service]["title"] == service_name:
                print("%s %s : removing rule for %s : %s/%s" %
                        (
                            table.name,
                            chain.name,
                            service,
                            rule.matches[0].parameters["dport"],
                            rule.get_protocol()
                        )
                )
                chain.delete_rule(rule)
    chain.set_policy("ACCEPT")
    table.commit()


if __name__ == "__main__":
    from sys import argv
    from datetime import date
    if len(argv) != 3:
        raise SystemExit("Syntax: %s iface up|down|connectivity-change"
                % argv[0])

    # In "pre-up" we don't get any connectivity at all, so no subnetwork.
    #if argv[2] == "up" or argv[2] == "pre-up":
    if argv[2] == "up":
        realm, essid = get_local_subnet()
        start_firewall(realm, essid)

    elif argv[2] == "down":
        with open(realm_pickle, "rb") as realm_fd:
            realm = pickle.load(realm_fd)
        with open(state_pickle, "rb") as state_fd:
            started_services = pickle.load(state_fd)
        with open(services_pickle, "rb") as services_fd:
            services = pickle.load(services_fd)
        stop_firewall(realm, started_services, services)

    elif argv[2] == "connectivity-change":
        # Not shure when NetworkManager does that ; we don't get any
        # new ip in environ anyway
        pass

