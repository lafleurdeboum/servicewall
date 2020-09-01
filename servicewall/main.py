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

from collections import namedtuple

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
#import arpreq
import subprocess



class ServiceWall(statefulfirewall.StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.
    """
    lib_dir = "/usr/lib/servicewall/"
    service_defs_pickle = "/usr/lib/servicewall/services.p"
    realm_defs_dict = "/etc/servicewall/realms.json"
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


    def start(self, check_hook=True, **args):
        """Will load a set of rules from self.realm_defs .
        """
        if check_hook:
            self._enable_hook()
        if self.realm_id not in self.realm_defs:
            # If we don't have a realm definition, load "ServiceWall:default"
            self.realm_defs[self.realm_id] = copy.deepcopy(self.realm_defs[self.identifier + ":default"])
        for service_name, scope in self.realm_defs[self.realm_id].items():
            self.insert_service_rule(service_name, scope=scope)
        # Commits the table if relevant, and brings other rules in :
        super().start(**args)

    def stop(self, check_hook=True):
        if check_hook:
            self._disable_hook()
        super().stop()

    def reload(self):
        self.stop(check_hook=False)
        self.start(check_hook=False)
        print("%s reloaded" % self.identifier)
    
    def enable(self):
        self._enable_in_systemd()

    def disable(self):
        self._disable_in_systemd()

    def _enable_hook(self):
        """Create a link in the network dispatcher pointing to the event triggerer.
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
                print("%s dispatcher was already linked" % dispatcher)
                linked = True
            else:
                print("%s dispatcher link created" % dispatcher)
                # symlink pointing to src in dst_dir
                os.symlink(self.lib_dir + self.dispatcher_toggler, dst_dir + self.dispatcher_toggler)
                linked = True
        if not linked:
            raise SystemExit("Could not link to any network event dispatcher. "
                    "You apparently aren't running neither Network Manager nor "
                    "systemd-networkd with networkd-dispatcher. You'll need one "
                    "of those to run this as it relies on them to fire the "
                    "network change events.")

    def _disable_hook(self):
        """Destroy the link in the network dispatcher pointing to the event triggerer.
        """
        for dispatcher, target in self.dispatchers.items():
            # DEBUG This test would fail on a broken link :
            if os.path.exists(target + self.dispatcher_toggler):
                os.remove(target + self.dispatcher_toggler)
                print("%s dispatcher link destroyed" % dispatcher)
            else:
                # Report missing link only if dir is present
                if os.path.exists(target):
                    print("there was no %s dispatcher link" % dispatcher)

    def save_rules(self):
        with open(self.realm_defs_dict, "w") as fd:
            json.dump(self.realm_defs, fd)
        print("saved realm defs to config")

    def allow_service(self, service_name, scope="local", realm=None):
        if service_name not in self.service_defs:
            raise KeyError("undefined service : %s." %
                    service_name)
        if realm == None:
            realm = self.realm_id
        # Create an entry for this realm's id if there weren't any :
        if realm not in self.realm_defs:
            self.realm_defs[realm] = copy.deepcopy(
                    self.realm_defs[self.identifier + ":default"])
        if service_name not in self.realm_defs[realm]:
            self.realm_defs[realm][service_name] = scope
            self.save_rules()
            print("added %s to realm def %s" %
                  (service_name, realm))
            # We cannot hot-load it, there's an order on rules, best is to reload :
            if realm == self.realm_id:
                self.reload()

    def insert_service_rule(self, service_name, scope="local"):
        """Open ports for a service hosted on this machine.

        service_name should be one of self.service_defs' keys.
        if src is "local", use self.subnetwork instead.
        """
        if scope == "local":
            src = self.subnetwork
        else:
            src = ""

        for rule in self.input_chain.rules:
            if super()._get_rule_name(rule) == service_name:
                raise KeyError("rule already in input chain")

        s = self.service_defs[service_name]
        print("allowing service %s from %s" %
              (service_name, src or "anywhere"))
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


    def disallow_service(self, service_name, realm=None):
        if realm == None:
            realm = self.realm_id
        # Create an entry for this realm's essid if there weren't any :
        if realm not in self.realm_defs:
            self.realm_defs[realm] = copy.deepcopy(self.realm_defs[self.identifier + ":default"])
        # Do our own validity testing
        if service_name not in self.service_defs:
            raise KeyError('service "%s" not found.')
        if service_name in self.realm_defs[realm]:
            del self.realm_defs[realm][service_name]
            self.save_rules()
            print("removed service %s from realm %s" %
                    (service_name, realm))
        else:
            raise KeyError('service "%s" was not allowed in realm %s anyway.'
                    % (service_name, realm))
        if realm == self.realm_id:
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

    def is_enabled(self):
        status = self._systemctl('is-enabled')
        if status != b'enabled':
            return False
        return True

    def _enable_in_systemd(self):
        self._systemctl('start')
        return self._systemctl('enable')

    def _disable_in_systemd(self):
        self._systemctl('stop')
        return self._systemctl('disable')

    def _systemctl(self, arg):
        try:
            return subprocess.check_output(['systemctl', arg, 'servicewall.service']).strip()
        except FileNotFoundError:
            raise AssertionError("'systemctl' not found in the path, is systemd installed on this machine ?")
        except subprocess.CalledProcessError:
            # systemctl returns an 'error' on is-enabled if the answer is False.
            pass

