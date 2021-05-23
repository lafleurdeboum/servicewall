"""Firewall class

implements a firewall using python-iptables
"""

from iptc import Rule, Rule6, Chain, Table, Table6
from iptc.ip4tc import IPTCError


class FireWall():
    """A simple firewall class

    In this firewall, there is (only) one _table called FILTER. It contains
    2 chains called input and output. When anything comes from outside, it
    goes through input. When anything goes outside, it goes through output.

    You can add (and delete) rules based on any valid iptables match.

    TODO :
    - ruleset Object.
    """

    identifier = "ServiceWall"

    def __init__(self):
        try:
            self._table = Table(Table.FILTER)
            self._table6 = Table6(Table6.FILTER)
        except IPTCError:
            # user is not root - return silently ; all writing ops will fail
            return

        # _table.autocommit is True by default.
        #self._table.autocommit = False
        self.input_chain = Chain(self._table, "INPUT")
        self.forward_chain = Chain(self._table, "FORWARD")
        self.output_chain = Chain(self._table, "OUTPUT")
        self.input_chain6 = Chain(self._table6, "INPUT")
        self.forward_chain6 = Chain(self._table6, "FORWARD")
        self.output_chain6 = Chain(self._table6, "OUTPUT")
        if self.status():
            self.up = True
        else:
            self.up = False

    def start(self):
        """Start a basic FireWall.

        Drops all incoming, accepts only localhost.
        """
        # Drop all incoming, allow outgoing requests.
        print("setting input policy to DROP")
        self.input_chain.set_policy("DROP")
        print("setting forward policy to DROP")
        self.forward_chain.set_policy("DROP")
        print("setting output policy to ACCEPT")
        self.output_chain.set_policy("ACCEPT")
        print("disabling ipv6 stack")
        self.input_chain6.set_policy("DROP")
        self.forward_chain6.set_policy("DROP")
        self.output_chain6.set_policy("DROP")
        # Accept all from _and_ to localhost.
        accept_localhost_rule = self.create_rule(
            "localhost",
            "ACCEPT",
            #siface="lo"
            src="127.0.0.1",
            dst="127.0.0.1"
            )
        self.input_chain.insert_rule(accept_localhost_rule)
        if not self._table.autocommit:
            self._table.commit()
        self.up = True

    def stop(self):
        """Remove rules.

        This function removes all rules created by this firewall's instances ;
        it recognizes them by the comment that's inside of them.
        """
        print("flushing rules")
        found_rules = 0
        for rule in self.input_chain.rules:
            if self._get_rule_id(rule) == self.identifier:
                self.del_rule(self._get_rule_name(rule), self.input_chain)
                found_rules += 1
        for rule in self.forward_chain.rules:
            if self._get_rule_id(rule) == self.identifier:
                self.del_rule(self._get_rule_name(rule), self.forward_chain)
                found_rules += 1
        if not found_rules:
            print("no rule found for id %s." % self.identifier)
        print("setting input policy to ACCEPT")
        self.input_chain.set_policy("ACCEPT")
        print("setting forward policy to ACCEPT")
        self.forward_chain.set_policy("ACCEPT")
        if not self._table.autocommit:
            self._table.commit()
        self.up = False

    def status(self):
        """print the status of the FireWall. Returns either True or False."""
        # Returns True if a single rule has our identifier tag
        is_up = False
        for rule in self.input_chain.rules:
            if self._get_rule_id(rule) == self.identifier:
                is_up = True
        return is_up

    def create_rule(self, name, target, dst="", dport="", src="", sport="", proto="", siface="", diface=""):
        """create and return a rule (or two if no proto given).

        name can be any string
        target is a string saying what to do, like
                "ACCEPT", "DENY", "DROP", "LOG"
        proto (if not defined, is assumed both udp and tcp)
        src is a realm in the form XXX.XXX.XXX.XXX/YY
        sport is source port. Currently ignored
        dst is a realm in the same form as src
        dport is destination port
        siface is the source interface
        diface is the destination interface
        """
        #print("adding rule %s" % name)
        if (dport or sport) and not proto:
            return [ self.create_rule(name,
                                      target,
                                      dst,
                                      dport,
                                      src,
                                      sport,
                                      proto,
                                      siface,
                                      diface) for proto in ("tcp", "udp") ]
        rule = Rule()
        rule.create_target(target)
        if dst:
            rule.dst = dst
        if dport:
            proto_match = rule.create_match(proto)
            proto_match.dport = str(dport)
            rule.protocol = proto
        if diface:
            rule.in_interface = diface
        if src:
            if src.count("-"):
                iprange_match = rule.create_match("iprange")
                iprange_match.src_range = src
                rule.add_match(iprange_match)
            else:
                rule.src = src
        if sport:
            proto_match = rule.create_match(proto)
            proto_match.sport = str(sport)
            rule.protocol = proto
        if siface:
            rule.out_interface = siface
        # Add a signature as a comment.
        comment_match = rule.create_match("comment")
        comment_match.comment = self.identifier + ":" + name
        rule.final_check()
        return rule

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
            # Find out dport - it's set by self.add_service_in as a match.
            dport = "any port"
            proto = "tcp/udp"
            for match in rule.matches:
                try:
                    dport = "port " + match.parameters["dport"]
                    proto = match.name
                except (KeyError, IndexError):
                    pass
            # Then find out source.
            if rule.src == "0.0.0.0/0.0.0.0":
                src = "any source"
            else:
                src = rule.src
            yield "%6s %-20s : %7s %-8s from %-23s" % (
                rule.target.name, self._get_rule_name(rule), proto, dport, src
            )

    def _get_rule_name(self, rule):
        for match in rule.matches:
            if match.comment:
                try:
                    _, rule_name = match.comment.split(":")
                except IndexError:
                    # No semicolon in comment
                    continue
                return rule_name

    def _get_rule_id(self, rule):
        for match in rule.matches:
            if match.comment:
                try:
                    rule_identifier, _ = match.comment.split(":")
                except IndexError:
                    # No semicolon in comment
                    continue
                return rule_identifier

