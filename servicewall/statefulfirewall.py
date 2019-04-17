"""  StateFulFireWall

Uses simple guidelines given in

and implements them in a FireWall class, using reasonable defaults.
"""

from systemd import journal
from iptc import Rule
from servicewall import firewall
from datetime import datetime


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


    def log_yielder(self, limit=None, period=None):
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
            i = 1
        if period:
            period = int(period)
        while True:
            log = reader.get_previous()
            if not "MESSAGE" in log:
                continue

            # Only catch messages sent by iptables log :
            if log["MESSAGE"].startswith(self.identifier):
                # Quit if log older than period :
                if period:
                    age = now - log["__REALTIME_TIMESTAMP"]
                    if int(age.total_seconds()) > period:
                        break
                message_dict = {}
                message = log["MESSAGE"].strip(self.identifier + ":").strip()
                message_dict["DATE"] = log["__REALTIME_TIMESTAMP"]
                for item in message.split():
                    if item.count("="):
                        key, value = item.split("=")
                        message_dict[key] = value
                    else:
                        message_dict[item] = ""
                # We count the number of logs with a destination port.
                if "DPT" not in message:
                    continue
                # Else raise limit counter :
                if limit:
                    if i > limit:
                        break
                    else:
                        i += 1

                yield message_dict


