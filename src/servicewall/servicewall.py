"""  ServiceWall

Uses service definitions provided by jhansonxi
and implements them in a FireWall class, either to allow them for the local
subnetwork, or worldwide.
"""

import pickle
from servicewall import network_helpers
from servicewall import statefulfirewall


class ServiceWall(statefulfirewall.StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.
    """

    identifier = "ServiceWall"
    conf_dir = "/usr/lib/servicewall/"
    service_defs_pickle = conf_dir + "services.p"
    realm_defs_pickle = conf_dir + "realms.p"

    def __init__(self):
        super().__init__()
        # TODO if the FW is already up, we need to check what was the
        # essid it connected to, to see if we need to reload.
        self.essid = network_helpers.get_essid()
        self.subnetwork = network_helpers.get_subnetwork()
        with open(self.service_defs_pickle, "rb") as fd:
            self.service_defs = pickle.load(fd)
        with open(self.realm_defs_pickle, "rb") as fd:
            self.realm_defs = pickle.load(fd)

    def start(self, **args):
        """Will load a set of rules from self.realm_defs . If these rules
        are set as True, they are matched with the provided subnetwork,
        else to any source.
        """
        if self.essid not in self.realm_defs:
            # If we don't have a definition in there, load "FireWall:new"
            self.realm_defs[self.essid] = self.realm_defs[identifier + ":new"]
        for service_name, local_toggle in self.realm_defs[self.essid].items():
            if local_toggle:
                self.add_service_in(service_name, local=True)
            else:
                self.add_service_in(service_name, local=False)
        super().start(**args)   # commits the table if relevant

    def save(self):
        """Dumps the actual config to config file.
        """
        with open(realm_defs_pickle, "wb") as fd:
            pickle.dump(self.realm_defs, fd)
        print("Modified realm rules for %s written to file." % self.essid)

    def add_service_in(self, service_name, local=False):
        """Open ports for a service hosted on this machine.
        
        service_name should be one of self.service_defs' keys.
        if src is "local", use self.subnetwork instead.
        """
        if service_name not in self.service_defs:
            raise KeyError("service_defs knows no service service_named %s."
                    % service_name)

        if local:
            src = self.subnetwork
        else:
            src = ""

        for port, proto in self.service_defs[service_name]["ports"]:
            self.add_rule(
                    service_name,
                    self.input_chain,
                    "ACCEPT",
                    src=src,
                    dport=port,
                    proto=proto,
            )

    def del_service_in(self, service_name):
        """Closes ports for service service_name if they were opened.
        """
        for rule in self.input_chain.rules:
            # Call the FireWall's  private _get_rule_name function
            if super()._get_rule_name(rule) == service_name:
                #self.del_rule(service_name, self.input_chain)
                self.input_chain.delete_rule(rule)


    def list_services_in(self):
        """Lists services for which we have allowed ports.
        """
        self.list_rules(self.input_chain)
