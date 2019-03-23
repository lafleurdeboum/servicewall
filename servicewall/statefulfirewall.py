"""  StateFulFireWall

Uses simple guidelines given in

and implements them in a FireWall class, using reasonable defaults.
"""

from iptc import Rule
from servicewall import firewall


class StateFulFireWall(firewall.FireWall):
    """Implement some useful stateful rules :
    
    - accept related/established packets
    - log anything that is dropped
    - drop invalid packets
    """

    identifier = "ServiceWall"

    def __init__(self):
        super().__init__()

    def start(self, **args):

        print("adding rule icmp")
        rule = Rule()
        rule.create_target("ACCEPT")
        rule.protocol = "icmp"
        m = rule.create_match("icmp")
        m.set_parameter("icmp-type", "8")
        comment_match = rule.create_match("comment")
        comment_match.comment = self.identifier + ":icmp"
        self.input_chain.append_rule(rule)

        # Top rule should be to allow related, established connections.
        self.add_conntrack_rule_in("ACCEPT", "ctstate", "RELATED,ESTABLISHED")

        # Log all that is refused.
        self.add_rule(
                "journalctl",
                self.input_chain,
                "LOG",
                position="bottom"
                )
 
        # Drop invalid packets - as diagnosed by the conntrack processor.
        self.add_conntrack_rule_in("DROP", "ctstate", "INVALID", position="bottom")

        super().start(**args)   # commits the table if relevant

    def add_conntrack_rule_in(self, target, param_key, param_value, position="top"):
        """Adds a rule to input chain, for example :

        StateFulFireWall.add_conntrack_rule_in("ACCEPT", "ctstate", "RELATED")
        """
        print("adding rule %s" % param_value)
        conntrack_rule = Rule()
        conntrack_rule.create_target(target)
        conntrack_match = conntrack_rule.create_match("conntrack")
        conntrack_match.set_parameter(param_key, param_value)
        comment_match = conntrack_rule.create_match("comment")
        comment_match.comment = self.identifier + ":" + param_value
        if position == "top":
            self.input_chain.insert_rule(conntrack_rule)
        elif position == "bottom":
            self.input_chain.append_rule(conntrack_rule)


