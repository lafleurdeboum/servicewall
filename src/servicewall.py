import pickle
from firewall import FireWall
from iptc import Rule


identifier = "FireWall"
conf_dir = "var/lib/braise/"
service_defs_pickle = conf_dir + "services.p"
realm_defs_pickle = conf_dir + "realms.p"


class StateFulFireWall(FireWall):
    """Implement some useful stateful rules :
    
    - accept related/established packets
    - drop invalid packets
    """
    def __init__(self):
        super().__init__()

    def start(self, **args):
        # Top rule should be to allow related, established connections.
        self.add_conntrack_rule_in("ACCEPT", "ctstate", "RELATED,ESTABLISHED")

        # Drop invalid packets - as diagnosed by the conntrack processor.
        self.add_conntrack_rule_in("DROP", "ctstate", "INVALID")
        super().start(**args)   # commits the table if relevant

    def add_conntrack_rule_in(self, target, param_key, param_value):
        """Adds a rule to input chain, for example :

        StateFulFireWall.add_conntrack_rule_in("ACCEPT", "ctstate", "RELATED")
        """
        print("adding rule %s" % param_value)
        conntrack_rule = Rule()
        conntrack_rule.create_target(target)
        conntrack_match = conntrack_rule.create_match("conntrack")
        conntrack_match.set_parameter(param_key, param_value)
        comment_match = conntrack_rule.create_match("comment")
        comment_match.comment = identifier + ":" + param_value
        self.input_chain.insert_rule(conntrack_rule)


class ServiceWall(StateFulFireWall):
    """ServiceWall - a FireWall in which you can add services on the fly.
    """
    def __init__(self):
        super().__init__()
        with open(service_defs_pickle, "rb") as fd:
            self.service_defs = pickle.load(fd)
        with open(realm_defs_pickle, "rb") as fd:
            self.realm_defs = pickle.load(fd)

    def start(self, essid, subnetwork, **args):
        """when you use start(), this object will load a set of rules
        defined per essid. If these rules are defined as a "local"
        subnetwork, they will be matched against the provided subnetwork."""
        self.essid = essid
        self.subnetwork = subnetwork
        if self.essid not in self.realm_defs.keys():
            self.realm_defs[self.essid] = self.realm_defs[identifier + ":new"]
        for service_name, local_toggle in self.realm_defs[self.essid].items():
            if local_toggle:
                self.add_service_in(service_name, local=True)
            else:
                self.add_service_in(service_name, local=False)
        super().start(**args)   # commits the table if relevant

    def save(self):
        print("writing modified realms")
        with open(realm_defs_pickle, "wb") as fd:
            pickle.dump(self.realm_defs, fd)

    def add_service_in(self, service_name, local=False):
        """Open ports for a service hosted on this machine.
        
        service_name should be one of self.service_defs' keys.
        if src is "local", use self.subnetwork instead.
        """
        try:
            service = self.service_defs[service_name]
        except KeyError as error:
            print("service_defs knows no service service_named %s."
                    % service_name)
            raise error

        # Add the service to realm_defs if it's not in there.
        if service_name not in self.realm_defs[self.essid].keys():
            if local == True:
                self.realm_defs[self.essid][service_name] = "local"
            else:
                self.realm_defs[self.essid][service_name] = ""

        if local == True:
            src = self.subnetwork
        else:
            src = ""

        for port, proto in service["ports"]:
            self.add_rule(
                    service_name,
                    self.input_chain,
                    "ACCEPT",
                    src=src,
                    dport=port,
                    proto=proto,
            )

    def del_service_in(self, service_name):
        for rule in self.input_chain.rules:
            # Call the FireWall's  private _get_rule_name function
            if super()._get_rule_name(rule) == service_name:
                self.del_rule(service_name, self.input_chain)
        for service in self.realm_defs[self.essid]:
            if service_name == service[0]:
                del self.realm_defs[self.essid][service_name]


    def list_services_in(self):
        self.list_rules(self.input_chain)
