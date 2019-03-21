"""  ServiceWall

Uses service definitions provided by jhansonxi
and implements them in a FireWall class, either to allow them for the local
subnetwork, or worldwide.
"""

from servicewall import network_helpers
from servicewall import statefulfirewall
# TODO should be loaded as a global from firewall.py through statefulfirewall.py
identifier = "ServiceWall"
#print(globals()["identifier"])

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


class ServiceWall(statefulfirewall.StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.
    """

    identifier = "ServiceWall"
    conf_dir = "/etc/servicewall/"
    lib_dir = "/usr/lib/servicewall/"
    realm_defs_dict = conf_dir + "realms.json"
    service_defs_pickle = lib_dir + "services.p"

    def __init__(self):
        super().__init__()
        # We need to know 2 things :
        # - wether we are online
        # - wether the firewall is enabled
        # TODO if the FW is already up, we need to check what was the
        # essid it connected to, to see if we need to reload.
        try:
            self.essid = network_helpers.get_essid()
            self.online = True
        except KeyError:    # We don't have any network connection.
            self.essid = False
            self.online = False

        if self.online:
            self.subnetwork = network_helpers.get_subnetwork()
        else:
            self.subnetwork = False

        with open(self.realm_defs_dict, "r") as fd:
            self.realm_defs = json.load(fd)
        with open(self.service_defs_pickle, "rb") as fd:
            self.service_defs = pickle.load(fd)

    def start(self, **args):
        """Will load a set of rules from self.realm_defs . If these rules
        are set as True, they are matched with the provided subnetwork,
        else to any source.
        """
        if self.online:
            if self.essid not in self.realm_defs:
                # If we don't have a realm definition, load "ServiceWall:default"
                self.realm_defs[self.essid] = self.realm_defs[identifier + ":default"]
            for service_name, local_toggle in self.realm_defs[self.essid].items():
                if local_toggle:
                    self.add_service_in(service_name, local=True)
                else:
                    self.add_service_in(service_name, local=False)
        # Commits the table if relevant, and brings other rules in :
        super().start(**args)

    def stop(self):
        if self.essid not in self.realm_defs:
            realm = identifier + ":default"
        else:
            realm = self.essid
        #for service_name in self.realm_defs[realm]:
        #    self.del_service_in(service_name)
        for rule in self.input_chain.rules:
            self.del_rule(super()._get_rule_name(rule), self.input_chain)

    def save_rules(self):
        """Dumps the actual config to config file.
        """
        with open(self.realm_defs_dict, "w") as fd:
            json.dump(self.realm_defs, fd)
        print("Modified realm rules for %s written to file %s." %
              (self.essid, self.realm_defs_dict))

    def add_service_in(self, service_name, local=False):
        """Open ports for a service hosted on this machine.
        
        service_name should be one of self.service_defs' keys.
        if src is "local", use self.subnetwork instead.
        """
        # Create an entry for this realm's essid if there weren't any :
        if self.essid not in self.service_defs:
            self.realm_defs[self.essid] = copy.deepcopy(self.realm_defs[identifier + ":default"])

        if service_name not in self.service_defs:
            raise KeyError("undefined service : %s."
                    % service_name)

        if service_name in self.realm_defs[self.essid]:
            print("%s is already allowed in realm %s" %
                  (service_name, self.essid))
        else:
            self.realm_defs[self.essid][service_name] = local

        if local:
            src = self.subnetwork
        else:
            src = ""

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
        """Closes ports for service service_name if they were opened.
        """
        # Create an entry for this realm's essid if there weren't any :
        if self.essid not in self.service_defs:
            self.realm_defs[self.essid] = copy.deepcopy(self.realm_defs[identifier + ":default"])
        # Do our own validity testing
        if service_name not in self.service_defs:
            raise KeyError('service "%s" not found. ')
        if service_name in self.realm_defs[self.essid]:
            del self.realm_defs[self.essid][service_name]
        else:
            raise KeyError('service "%s" was not allowed in realm %s anyway.'
                    % (service_name, self.essid))
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


