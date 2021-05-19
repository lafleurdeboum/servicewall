"""  StateFulFireWall

Uses simple guidelines given in

and implements them in a FireWall class, using reasonable defaults.
"""

from datetime import datetime
import socket
from systemd import journal
from iptc import Rule
from servicewall import firewall


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

    def start(self, **args):
        print("adding rule icmp")
        rule = Rule()
        rule.create_target("ACCEPT")
        rule.protocol = "icmp"
        icmp_match = rule.create_match("icmp")
        icmp_match.set_parameter("icmp-type", "8")
        comment_match = rule.create_match("comment")
        comment_match.comment = self.identifier + ":icmp"
        self.input_chain.append_rule(rule)

        # Top rule should be to allow related, established connections.
        related_rule = self.create_conntrack_rule("ACCEPT",
                                                  "ctstate",
                                                  "RELATED,ESTABLISHED")
        self.input_chain.insert_rule(related_rule)

        # Drop igmp packets before logging.
        drop_igmp_rule = Rule()
        drop_igmp_rule.create_target("DROP")
        drop_igmp_rule.protocol = "igmp"
        self.input_chain.append_rule(drop_igmp_rule)
        # Log all that is refused in INPUT chain.
        log_rule = self.create_log_rule("not in allowed services", group="1")
        self.input_chain.append_rule(log_rule)

        # Drop invalid packets - as diagnosed by the conntrack processor.
        # Note that this rule is useless because packets would be dropped anyway.
        invalid_rule = self.create_conntrack_rule("DROP", "ctstate", "INVALID")
        self.input_chain.append_rule(invalid_rule)

        super().start(**args)   # commits the table if relevant

    def create_conntrack_rule(self, target, param_key, param_value):
        """creates a connection tracking rule, for example :

        StateFulFireWall.create_conntrack_rule("ACCEPT", "ctstate", "RELATED")
        """
        print("adding rule %s" % param_value)
        conntrack_rule = Rule()
        conntrack_rule.create_target(target)
        conntrack_match = conntrack_rule.create_match("conntrack")
        conntrack_match.set_parameter(param_key, param_value)
        comment_match = conntrack_rule.create_match("comment")
        comment_match.comment = self.identifier + ":" + param_value
        return conntrack_rule


    def create_log_rule(self, comment="", group="", dst="", dport="", src="",
                        sport="", proto="", iface=""):
        """Adds a log rule

        All arguments should be strings !
        The comment size is limited to 64 characters as a whole.
        The nflog_group is the one you will have to select in ulogd.
        """
        log_rule = self.create_rule("log", "NFLOG", dst, dport, src, sport,
                                    proto, iface)
        limit_match = log_rule.create_match("limit")
        limit_match.limit = "1/s"
        limit_match.limit_burst = "1"
        if comment:
            log_rule.target.set_parameter("nflog-prefix", comment)
        if group:
            log_rule.target.set_parameter("nflog-group", str(group))
        return log_rule


    def yield_logs(self, limit=None, period=None):
        """get logs we implemented in iptables from journald

        limit [int] is the max number of logs to yield
        period [int] is the age in seconds of the oldest log to yield
        """
        reader = journal.Reader()
        #reader.log_level(journal.LOG_WARNING)
        # That would be for LOG match :
        #reader.add_match(SYSLOG_IDENTIFIER="kernel")
        # That is for ulog systemd service associated to ulog.socket :
        reader.add_match(_SYSTEMD_UNIT="servicewall-logs.service")
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
            if "MESSAGE" not in log:
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
            # conntrack info log - skip.
            if message.startswith("[NEW]") or message.startswith("[DESTROY]"):
                continue

            # Only count the logs that make it here :
            if limit:
                if i < limit:
                    i += 1
                else:
                    break

            message_dict["LOG_DATE"] = log["__REALTIME_TIMESTAMP"]
            for item in message.split():
                if item.count("="):
                    key, value = item.split("=")
                    message_dict[key] = value
                else:
                    message_dict[item] = ""

            if 'DPT' not in message_dict:
                message_dict['DPT'] = ''
            if 'SPT' not in message_dict:
                message_dict['SPT'] = ''
            if message_dict['PROTO'].isnumeric():
                message_dict['PROTO'] = self.protobynumber[
                        int(message_dict['PROTO'])]
            else:
                message_dict['PROTO'] = message_dict['PROTO'].lower()

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
                    if i < limit:
                        i += 1
                    else:
                        # Stop at step i+1 and pop last record :
                        logs.popitem()
                        break
            else:
                logs[log[criteria]].append(log)
        return logs

