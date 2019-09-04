"""  StateFulFireWall

Uses simple guidelines given in

and implements them in a FireWall class, using reasonable defaults.
"""

from systemd import journal
from iptc import Rule
from servicewall import firewall
from datetime import datetime
import socket


class StateFulFireWall(firewall.FireWall):
    """Implement some useful stateful rules :
    
    - accept related/established packets
    - log anything that is dropped
    - drop invalid packets
    """
    protobynumber = { num: name[8:].lower()
                 for name, num in vars(socket).items()
                 if name.startswith("IPPROTO")
    }
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
                "nflog",
                self.input_chain,
                "NFLOG",
                position="bottom",
        )
        self.add_rule(
                "nflog",
                self.forward_chain,
                "NFLOG",
                position="bottom",
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


    def yield_logs(self, limit=None, period=None):
        """get logs we implemented in iptables from journald"""
        reader = journal.Reader()
        #reader.log_level(journal.LOG_WARNING)
        # That would be for LOG match :
        #reader.add_match(SYSLOG_IDENTIFIER="kernel")
        # That is for ulog systemd service associated to ulog.socket :
        reader.add_match(_SYSTEMD_UNIT="ulog.service")
        now = datetime.now()
        hostname = socket.gethostname()
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
            # Quit if log older than period :
            if period:
                age = now - log["__REALTIME_TIMESTAMP"]
                if int(age.total_seconds()) > period:
                    break
            message_dict = {}
            # Get rid of the trailing date and hostname :
            try:
                message = log["MESSAGE"].split(hostname)[-1].strip()
            except IndexError:
                print("!! error :")
                print(log["MESSAGE"])

            # If message begins with "[NEW] "or "[DESTROY]", then it is a
            # conntrack info cut after the "ORIG:" and "REPLY:" tags.
            if message.startswith("[NEW]"):
                message_dict["conntrack_type"] = "new"
            if message.startswith("[DESTROY]"):
                message_dict["conntrack_type"] = "destroy"

            # We may consider the number of logs with a destination port :
            # "DPT" not in message:
            #    continue

            if limit:
                if i > limit:
                    break
                else:
                    i += 1

            message_dict["date"] = log["__REALTIME_TIMESTAMP"]

            if "conntrack_type" in message_dict:
                orig, reply = message.split(", REPLY: ")
                orig = orig.split("ORIG: ")[1]
                message_dict["orig"] = {}
                message_dict["reply"] = {}
                for item in orig.split():
                    if item.count("="):
                        key, value = item.split("=")
                        message_dict["orig"][key] = value
                    else:
                        message_dict["orig"][key] = ""
                for item in reply.split():
                    if item.count("="):
                        key, value = item.split("=")
                        message_dict["reply"][key] = value
                    else:
                        message_dict["reply"][key] = ""
                    if "SPT" not in message_dict["orig"]:
                        message_dict["orig"]["SPT"] = ""
                    message_dict["id"] = "%s %s %s %s" % (
                                message_dict["orig"]["SRC"],
                                message_dict["reply"]["SRC"],
                                message_dict["orig"]["PROTO"],
                                message_dict["orig"]["DPT"],
                    )
            else:
                message_dict["message"] = {}
                for item in message.split():
                    if item.count("="):
                        key, value = item.split("=")
                        message_dict["message"][key] = value
                    else:
                        message_dict["message"][item] = ""
            yield message_dict

    def filter_logs_by(self, criteria, limit=None, period=None):
        """output logs sorted by a log variable, like "DPT" or "SRC"

        note that limit applies to the criteria (like sort nth first SRC hosts)
        """
        yielder = self.yield_logs(period=period)
        logs = {}
        if limit:
            limit = int(limit)
            i = 0
        if period:
            period = int(period)
        for log in yielder:
            if log[criteria] not in logs:
                logs[log[criteria]] = [log, ]
                if limit:
                    if i >= limit:
                        # Stop at step i+1 and pop last record :
                        logs.popitem()
                        break
                    else:
                        i += 1
            else:
                logs[log[criteria]].append(log)
        return logs

