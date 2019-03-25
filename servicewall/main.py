"""  ServiceWall

Uses service definitions provided by jhansonxi
and implements them in a FireWall class, either to allow them for the local
subnetwork, or worldwide.

This firewall records the services you allow your computer to serve on a
specific network profile, switching between profiles as network provider
changes.

"""

from servicewall import network_helpers
from servicewall import statefulfirewall
# TODO should be loaded as a global from firewall.py through statefulfirewall.py
identifier = "ServiceWall"
#print(globals()["identifier"])

from collections import namedtuple
from systemd import journal
from datetime import datetime

#from servicewall import service_helpers
#globals()["PortDef"] = service_helpers.PortDef
#globals()["ServiceDef"] = service_helpers.ServiceDef

from servicewall.service_helpers import PortDef, ServiceDef
globals()["PortDef"] = PortDef
globals()["ServiceDef"] = ServiceDef
import pickle
import json
import copy
import os
import arpreq


class ServiceWall(statefulfirewall.StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.
    """
    identifier = "ServiceWall"
    lib_dir = "/usr/lib/servicewall/"
    service_defs_pickle = "/usr/lib/servicewall/services.p"
    realm_defs_dict = "/etc/servicewall/realms.json"
    config_file = "/etc/servicewall/config.json"
    dispatchers = {
        "Network Manager": "/etc/NetworkManager/dispatcher.d/",
        "systemd-networkd": "/etc/networkd-dispatcher/carrier.d/",
    }
    dispatcher_toggler = "toggler"

    def __init__(self):
        super().__init__()
        # We need to know 2 things :
        #   - wether the firewall is enabled
        #   - wether we are online and on which network realm

        with open(self.config_file, 'r') as fd:
            self.config = json.load(fd)
        with open(self.realm_defs_dict, "r") as fd:
            self.realm_defs = json.load(fd)
        with open(self.service_defs_pickle, "rb") as fd:
            self.service_defs = pickle.load(fd)
        try:
            self.realm_id = network_helpers.get_realm_id()
            self.online = True
        except KeyError:    # We don't have any network connection.
            self.realm_id = None
            self.online = False

        if self.online:
            self.subnetwork = network_helpers.get_subnetwork()
        else:
            self.subnetwork = False


    def start(self, **args):
        """Will load a set of rules from self.realm_defs . If these rules
        are set as True, they are matched with the provided subnetwork,
        else to any source.
        """
        if self.config["enabled"]:
            if self.online:
                if self.realm_id not in self.realm_defs:
                    # If we don't have a realm definition, load "ServiceWall:default"
                    self.realm_defs[self.realm_id] = copy.deepcopy(self.realm_defs[identifier + ":default"])
                for service_name, local_toggle in self.realm_defs[self.realm_id].items():
                    if local_toggle:
                        self.insert_service_rule(service_name, local=True)
                    else:
                        self.insert_service_rule(service_name, local=False)
        else:
            raise SystemExit("not starting, firewall disabled. Enable it with\n\t# braise enable")
        # Commits the table if relevant, and brings other rules in :
        super().start(**args)

    def stop(self):
        if self.config["enabled"]:
            # DEBUG should only remove rules from ServiceWall
            for rule in self.input_chain.rules:
                self.del_rule(super()._get_rule_name(rule), self.input_chain)
        else:
            raise SystemExit("not stopping, firewall disabled. Enable it with\n\t# braise enable")

    def reload(self):
        self.stop()
        self.start()
        print("%s reloaded" % self.identifier)

    def enable(self):
        """Create a link in the network dispatcher pointing to the event triggerer,
        and start the firewall.
        """
        if not os.path.exists(self.lib_dir):    # Should be installed by setup.py .
            raise SystemExit("Could not find %s in %s. Check your installation !" %
                    (dispatcher_toggler, self.lib_dir))
        # We will only mark as enabled if we can link to a network dispatcher :
        linked = False
        for dispatcher, dst_dir in self.dispatchers.items():
            if not os.path.exists(dst_dir):
                # Keep going with the next dispatcher.
                continue
            if os.path.exists(dst_dir + self.dispatcher_toggler):
                print("  %s dispatcher was already enabled" % dispatcher)
                linked = True
            else:
                print("  enabling %s dispatcher" % dispatcher)
                # symlink pointing to src in dst_dir
                os.symlink(self.lib_dir + self.dispatcher_toggler, dst_dir + self.dispatcher_toggler)
                linked = True
        if linked:
            # Mark as enabled :
            self.config["enabled"] = True
            with open(self.config_file, 'w') as fd:
                 json.dump(self.config, fd)
        else:
            raise SystemExit("Could not link to any network event dispatcher. "
                    "You apparently aren't running neither Network Manager nor "
                    "systemd-networkd with networkd-dispatcher. You'll need one "
                    "of those to run this self as it relies on them to fire the "
                    "network change events.")
        if self.up:
            self.reload()
            print("%s was already up, reloaded" % self.identifier)
        else:
            self.start()
            print("%s enabled" % self.identifier)

    def disable(self):
        """Destroy the link in the network dispatcher pointing to the event triggerer,
        and stop the firewall.
        """
        for dispatcher, target in self.dispatchers.items():
            # DEBUG This test would fail on a broken link :
            if os.path.exists(target + self.dispatcher_toggler):
                os.remove(target + self.dispatcher_toggler)
                print("Network dispatcher %s disabled" % dispatcher)
            else:
                # Report missing link only if dir is present
                if os.path.exists(target):
                    print("%s dispatcher was already disabled" % dispatcher)
        self.stop()
        if self.config["enabled"]:
            # Mark as disabled:
            self.config["enabled"] = False
            with open(self.config_file, 'w') as fd:
                json.dump(self.config, fd)
            print("%s disabled" % self.identifier)
        else:
            print("%s was already disabled" % self.identifier)

    def save_rules(self):
        with open(self.realm_defs_dict, "w") as fd:
            json.dump(self.realm_defs, fd)
        print("saved realm defs to config")

    def add_service_in(self, service_name, local=False):
        # Create an entry for this realm's essid if there weren't any :
        if self.realm_id not in self.realm_defs:
            self.realm_defs[self.realm_id] = copy.deepcopy(self.realm_defs[identifier + ":default"])
        if service_name not in self.service_defs:
            raise KeyError("undefined service : %s." %
                    service_name)
        if service_name not in self.realm_defs[self.realm_id]:
            self.realm_defs[self.realm_id][service_name] = local
            self.save_rules()
            print("added %s to realm def %s" %
                  (service_name, self.realm_id))
            self.reload()

    def insert_service_rule(self, service_name, local=False):
        """Open ports for a service hosted on this machine.

        service_name should be one of self.service_defs' keys.
        if src is "local", use self.subnetwork instead.
        """
        if local:
            src = self.subnetwork
        else:
            src = ""

        for rule in self.input_chain.rules:
            if super()._get_rule_name(rule) == service_name:
                raise KeyError("rule already in input chain")

        s = self.service_defs[service_name]
        print("allowing service %s from %s" %
              (service_name, local and src or "any"))
        for port in s.ports.tcp:
            self.add_rule(service_name,
                         self.input_chain,
                         "ACCEPT",
                         src=src,
                         dport=port,
                         proto="tcp"
            )
        for port in s.ports.udp:
            self.add_rule(service_name,
                         self.input_chain,
                         "ACCEPT",
                         src=src,
                         dport=port,
                         proto="udp"
            )


    def del_service_in(self, service_name):
        # Create an entry for this realm's essid if there weren't any :
        if self.realm_id not in self.realm_defs:
            self.realm_defs[self.realm_id] = copy.deepcopy(self.realm_defs[identifier + ":default"])
        # Do our own validity testing
        if service_name not in self.service_defs:
            raise KeyError('service "%s" not found.')
        if service_name in self.realm_defs[self.realm_id]:
            del self.realm_defs[self.realm_id][service_name]
            self.save_rules()
            print("removed service %s from realm %s" %
                    (service_name, self.realm_id))
        else:
            raise KeyError('service "%s" was not allowed in realm %s anyway.'
                    % (service_name, self.realm_id))
        self.remove_service_rule(service_name)

    def remove_service_rule(self, service_name):
        """Closes ports for service service_name if they were opened.
        """
        for rule in self.input_chain.rules:
            # Call the FireWall's  private _get_rule_name function
            if super()._get_rule_name(rule) == service_name:
                self.del_rule(service_name, self.input_chain)
                #self.input_chain.delete_rule(rule)


    def list_services_in(self):
        """Lists services for which we have allowed ports.
        """
        self.list_rules(self.input_chain)

    def list_services_by_port(self, port):
        services_list = []
        for service_name, s_tuple in self.service_defs.items():
            for service_port_range in (*s_tuple.ports.tcp, *s_tuple.ports.udp):
                # service_port_range is a string containing either a number or a
                # range, as in "80:88", "120"
                if service_port_range.isalnum():
                    if port == service_port_range:
                        services_list.append(service_name)
                else:   # it's a range
                    start, end = service_port_range.split(":")
                    if port in range(int(start), int(end)+1):
                        services_list.append(service_name)
        return services_list


    def log_yielder(self, limit=None, period=""):
        """get logs we implemented in iptables from journald"""
        # Equivalent to :
        #   journalctl --identifier kernel -p warning | grep ServiceWall
        reader = journal.Reader()
        reader.log_level(journal.LOG_WARNING)
        reader.add_match(SYSLOG_IDENTIFIER="kernel")
        now = datetime.today()
        #p = select.poll()
        #p.register(reader, reader.get_events())
        #p.poll()
        reader.seek_tail()
        if limit:
            limit = int(limit)
            i = 0
        while True:
            log = reader.get_previous()
            if not "MESSAGE" in log:
                continue

            # Only catch messages sent by iptables log :
            if log["MESSAGE"].startswith(self.identifier):
                message_dict = {}
                message = log["MESSAGE"].strip(self.identifier + ":").strip()
                message_dict["DATE"] = log["__REALTIME_TIMESTAMP"]
                for item in message.split():
                    if item.count("="):
                        key, value = item.split("=")
                        message_dict[key] = value
                    else:
                        message_dict[item] = ""
                if "DPT" not in message:
                    continue
                # Quit if log older than period :
                if period:
                    age = datetime.timestamp(now) - datetime.timestamp(log["__REALTIME_TIMESTAMP"])
                    if age > period:
                        break
                if limit:
                    if i >= limit:
                        break
                    else:
                        i += 1
                yield message_dict


