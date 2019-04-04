"""Firewall class

implements a firewall using python-iptables
"""

from os import environ
from iptc import Rule, Match, Chain, Table
from iptc.ip4tc import IPTCError


identifier = "ServiceWall"


class FireWall():
    """A simple firewall class

    In this firewall, there is (only) one _table called FILTER. It contains
    2 chains called input and output. When anything comes from outside, it
    goes through input. When anything goes outside, it goes through output.

    You can add (and delete) rules based on any valid iptables match.

    TODO :
    - ruleset Object.
    """
    def __init__(self):
        try:
            self._table = Table(Table.FILTER)
        except IPTCError:
            # user is not root - return silently ; all writing ops will fail
            return

        # _table.autocommit is True by default.
        #self._table.autocommit = False
        self.input_chain = Chain(self._table, "INPUT")
        self.output_chain = Chain(self._table, "OUTPUT")
        if self.status():
            self.up = True
        else:
            self.up = False

    def start(self):
        """Start a basic FireWall.

        Drops all incoming, accepts only localhost.
        """
        # Drop all incoming. Basic but functional.
        print("setting input policy to DROP")
        self.input_chain.set_policy("DROP")
        self.output_chain.set_policy("ACCEPT")
        # Accept all on localhost.
        self.add_rule(
                "localhost",
                self.input_chain,
                "ACCEPT",
                iface="lo"
                )
        if not self._table.autocommit:
            self._table.commit()
        self.up = True

    def stop(self):
        """Remove rules.

        This function removes all rules created by this firewall's instances ;
        it recognizes them by the comment that's inside of them.
        """
        found_rules = 0
        for rule in self.input_chain.rules:
            name = self._get_rule_name(rule)
            ident = self._get_rule_id(rule)
            if ident == identifier:
                self.del_rule(self._get_rule_name(rule), self.input_chain)
                found_rules += 1
        if not found_rules:
            print("no rule found for id %s." % identifier)
        print("setting input policy to ACCEPT")
        self.input_chain.set_policy("ACCEPT")
        if not self._table.autocommit:
            self._table.commit()
        self.up = False

    def status(self):
        """print the status of the FireWall. Returns either True or False."""
        # Returns True if a single rule has our identifier tag
        for rule in self.input_chain.rules:
            if identifier == self._get_rule_id(rule):
                return True
        else:
            return False

    def add_rule(self, name, chain, target, dst="", dport="", src="", sport="", proto="", iface="", position="top"):
        """Add a rule to the input chain self.input_chain.

        chain should be either self.input_chain or self.output_chain.
        name can be any string
        target is a string saying what to do, like
                "ACCEPT", "DENY", "DROP", "LOG"
        proto (if not defined, is assumed both udp and tcp)
        src is a realm in the form XXX.XXX.XXX.XXX/YY
        sport is source port. Currently ignored
        dst is a realm in the same form as src
        dport is destination port
        iface is the interface, will be in_interface if chain is the input chain.
                                       out_interface if chain is the output chain.
        """
        #print("adding rule %s" % name)
        if (dport or sport) and not proto:
            for proto in "tcp", "udp":
                self.add_rule(name, chain, target, dst, dport, src, sport, proto, iface)
        else:
            rule = Rule()
            rule.create_target(target)
            if target == "LOG":
                limit_match = rule.create_match("limit")
                limit_match.limit = "1/s"
                limit_match.limit_burst = "1"
                rule.target.set_parameter("log-prefix", identifier + ":")
            # First we need to know if we go in or out
            # Then some rules need the creation of a match
            if dst:
                rule.dst = dst
            if dport:
                proto_match = rule.create_match(proto)
                proto_match.dport = str(dport)
                rule.protocol = proto
            if src:
                rule.src = src
            if sport:
                proto_match = rule.create_match(proto)
                proto_match.sport = str(sport)
                rule.protocol = proto
            if iface:
                if chain.name == self.input_chain.name:
                    rule.in_interface = iface
                elif chain.name == self.output_chain.name:
                    rule.out_interface = iface
                if src == dst:
                    print("warning, both source and dest are set to %s" % src)
           # Add a signature as a comment.
            comment_match = rule.create_match("comment")
            comment_match.comment = identifier + ":" + name
            # Try to set it into chain.
            rule.final_check()
            if position == "bottom":
                chain.append_rule(rule)
            elif position == "top":
                chain.insert_rule(rule)
            else:
                raise SystemError("position should be top or bottom")
            if not rule in chain.rules:
                print("Need to check %s rule." % name)

    def del_rule(self, name, chain):
        """Remove rule.

        This function removes one rule named "name" in chain "chain". It
        expects the rule to contain a comment in the form
            "identifier:name"
        where identifier is the name of the program that has set the rule, and
        title is the name of the rule. Note that there may be several rules
        under the same name. This should delete the first it finds.
        """
        for rule in chain.rules:
            if self._get_rule_name(rule) == name:
                chain.delete_rule(rule)
                #print("deleted rule %s" % name)
                break

    def list_rules(self, chain):
        for rule in chain.rules:
            # First find out dport - it gets set by self.add_service_in as a match.
            dport = "any"
            proto = "any"
            for match in rule.matches:
                try:
                    dport = match.parameters["dport"]
                    proto = match.name
                except (KeyError, IndexError):
                    pass
            # Then find out source.
            if rule.src == "0.0.0.0/0.0.0.0":
                src = "any"
            else:
                src = rule.src
            print("%s %s\t\t: %s port %s from %s" %
                    (rule.target.name, self._get_rule_name(rule),
                        proto, dport, src))

    def _get_rule_name(self, rule):
        for match in rule.matches:
            if match.comment:
                try:
                    rule_identifier, rule_name = match.comment.split(":")
                except IndexError:
                    # No semicolon in comment
                    continue
                return rule_name

    def _get_rule_id(self, rule):
        for match in rule.matches:
            if match.comment:
                try:
                    rule_identifier, rule_name = match.comment.split(":")
                except IndexError:
                    # No semicolon in comment
                    continue
                return rule_identifier

