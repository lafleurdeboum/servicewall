"""  ServiceWall

Uses service definitions provided by jhansonxi
and implements them in a FireWall class, either to allow them for the local
subnetwork, or worldwide.

This firewall records the services you allow your computer to serve on a
specific network profile, switching between profiles as network provider
changes.

"""

import pickle
import json
import copy
import os
import subprocess
from collections import namedtuple

from servicewall import network_helpers
from servicewall import statefulfirewall

# from servicewall import service_helpers
# globals()["PortDef"] = service_helpers.PortDef
# globals()["ServiceDef"] = service_helpers.ServiceDef

from servicewall.service_helpers import PortDef, ServiceDef
globals()["PortDef"] = PortDef
globals()["ServiceDef"] = ServiceDef


def _systemctl(arg):
    try:
        retval = subprocess.check_output(['systemctl',
                                          arg,
                                          'servicewall.service'])
        return retval.decode().strip()
    except FileNotFoundError:
        raise AssertionError("'systemctl' not found in the path, is systemd"
                             " installed on this machine ?")
    except subprocess.CalledProcessError:
        # systemctl returns an 'error' on is-enabled if the answer is False.
        pass


def _enable_in_systemd():
    return _systemctl('enable')


def _disable_in_systemd():
    return _systemctl('disable')


class ServiceWall(statefulfirewall.StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.

    This class supersedes StateFulFireWall and adds services and realms.
    self.service_defs is a dict containing service definitions stored in
    self.service_defs_pickle, additioned with defs in self.service_defs_dir
    A service def file should be a json definition that is a valid ServiceDef.
    You can get a valid sample with eg

        braise show service http

    You can try yours with

        import json
        from servicewall.service_helpers import ServiceDef
        with open(your_file, "rb") as fd:
            service_dict = json.load(fd)
            print(ServiceDef(service_dict))
    """
    config_file = "/etc/servicewall/config.cfg"
    lib_dir = "/usr/lib/servicewall/"
    realm_defs_dict = "/etc/servicewall/realms.json"
    service_defs_pickle = "/usr/lib/servicewall/services.p"
    service_defs_dir = "/etc/servicewall/services/"
    dispatcher_toggler = "toggler"
    dispatchers = {
        "Network Manager": "/etc/NetworkManager/dispatcher.d/",
        "systemd-networkd": "/etc/networkd-dispatcher/carrier.d/",
    }

    def __init__(self):
        super().__init__()
        with open(self.realm_defs_dict, "r") as fd:
            self.realm_defs = json.load(fd)
        with open(self.service_defs_pickle, "rb") as fd:
            self.service_defs = pickle.load(fd)
        for service_file in os.listdir(self.service_defs_dir):
            if service_file.find('.') == 0:
                # It's a dotfile, keep going
                continue
            try:
                with open(self.service_defs_dir + service_file) as fd:
                    service_def = json.load(fd)
                    service_def["ports"] = PortDef(**service_def["ports"])
                    sdef = ServiceDef(**service_def)
                    self.service_defs[sdef.title] = sdef
            except TypeError as error:
                print("Warning : ServiceDef." + str(error),
                      "in " + self.service_defs_dir + service_file)
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


    def start(self, should_check_hook=True, **args):
        """Will load a set of rules from self.realm_defs .
        """
        if should_check_hook:
            self._enable_hook()
        if self.realm_id not in self.realm_defs:
            # If we don't have a realm definition, load "ServiceWall:default"
            self.realm_defs[self.realm_id] = copy.deepcopy(
                self.realm_defs[self.identifier + ":default"])
        for service_name, scope in self.realm_defs[self.realm_id].items():
            self.insert_service_rule(service_name, scope=scope)
        # Commits the table if relevant, and brings other rules in :
        super().start(**args)

    def stop(self, should_check_hook=True):
        if should_check_hook:
            self._disable_hook()
        super().stop()

    def reload(self):
        self.stop(should_check_hook=False)
        self.start(should_check_hook=False)
        print("%s reloaded" % self.identifier)

    def enable(self):
        try:
            _enable_in_systemd()
        except AssertionError:
            with open(self.config_file, 'w+') as fd:
                fd.write('{ "state": "enabled" }')

    def disable(self):
        try:
            _disable_in_systemd()
        except AssertionError:
            with open(self.config_file, 'w+') as fd:
                fd.write('{ "state": "disabled" }')

    def is_enabled(self):
        try:
            status = _systemctl('is-enabled')
        except AssertionError:
            with open(self.config_file, 'r') as fd:
                config = json.load(fd)
                status = config["state"]
        if status != 'enabled':
            return False
        return True

    def allow_service(self, service_name, scope="local", realm=None):
        if service_name not in self.service_defs:
            raise KeyError("undefined service : %s." %
                           service_name)
        if realm is None:
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
        elif scope == "docker":
            src = "172.16.0.0-172.31.255.255"
        else:
            src = ""

        for rule in self.input_chain.rules:
            if super()._get_rule_name(rule) == service_name:
                raise KeyError("rule already in input chain")

        service = self.service_defs[service_name]
        print("allowing service %s from %s" %
              (service_name, src or "anywhere"))
        for port in service.ports.tcp:
            rule = self.create_rule(service_name,
                                    "ACCEPT",
                                    src=src,
                                    dport=port,
                                    proto="tcp"
                                    )
            self.input_chain.insert_rule(rule)
        for port in service.ports.udp:
            rule = self.create_rule(service_name,
                                    "ACCEPT",
                                    src=src,
                                    dport=port,
                                    proto="udp"
                                    )
            self.input_chain.insert_rule(rule)

    def disallow_service(self, service_name, realm=None):
        if realm is None:
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

    def save_rules(self):
        with open(self.realm_defs_dict, "w") as fd:
            json.dump(self.realm_defs, fd, indent=2)
        print("saved realm defs to config")

    def list_services_in(self):
        """Lists services for which we have allowed ports.
        """
        self.list_rules(self.input_chain)

    def list_services_by_port(self, port):
        services_list = []
        for service_name, s_tuple in self.service_defs.items():
            for service_port_range in (*s_tuple.ports.tcp, *s_tuple.ports.udp):
                # service_port_range is a string containing either a number or
                # a range, as in "80:88", "120"
                if service_port_range.isalnum():
                    if port == service_port_range:
                        services_list.append(service_name)
                else:   # it's a range
                    start, end = service_port_range.split(":")
                    if port in range(int(start), int(end)+1):
                        services_list.append(service_name)
        return services_list

    def _enable_hook(self):
        """Create a link in the network dispatcher pointing to the event triggerer.
        """
        if not os.path.exists(self.lib_dir):
            # Should be installed by setup.py .
            raise SystemExit("Could not find %s in %s. Check your installation"
                             % (self.dispatcher_toggler, self.lib_dir))
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
                os.symlink(self.lib_dir + self.dispatcher_toggler,
                           dst_dir + self.dispatcher_toggler)
                linked = True
        if not linked:
            raise SystemExit("Could not link to any network event dispatcher. "
                             "You apparently aren't running neither Network "
                             "Manager nor systemd-networkd with "
                             "networkd-dispatcher. You'll need one of those to"
                             " run this as it relies on them to fire the"
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

