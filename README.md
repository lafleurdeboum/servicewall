# ServiceWall

This firewall adapts to the changes in the connection name (the ESSID), using
a set of rules for each of these realms.

Install it with
 `# pip install servicewall`

The firewall is disabled by default. To enable it now and at boot-time:
 # braise enable

Once started, the default behaviour is to drop all that come in, excepted for
some community-useful services (details on this later). All that go out is
allowed.

To have details on the status, use
 # braise show status
If it doesn't reply at all, then the firewall is down.

To allow a specific service, do
 # braise add Service Name
which will add this service to this realm's definition. If you connect to
internet in another place, the rules for this place (identified by the ESSID of
the connection) will be put aside, and brought back when you connect to it
again.

Don't know what's the name of the service you want to allow ? You'll need to
 # braise show services
be careful, the list is quite long. Once you want exhaustive informations on a
single service, do
 # braise show service Service Name

These rules are stored in a dictionary called realm_defs. To interrogate it, do
 # braise show realms

And in the end, the firewall logs all that it drops ; there's a log processor
tool included ; try it with
 # braise show logs
or
 # braise show logs since NUMBER_OF_SECONDS


[GNU](http://www.gnu.org) Version 3 license
