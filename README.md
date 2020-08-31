# ServiceWall


## What to expect

ServiceWall is a firewall intended for laptops and all devices that connect to
several different networks. It will drop incoming requests, excepted for those
that you allow. Each service you allow in will be remembered either :
- for the network you're connected to (the realm's ruleset), or
- for unregistered networks (the default ruleset)

At the moment the default ruleset is : accept `ssh` and `DHCP` incoming 
connections. `ssh` connections are accepted from anywhere, whereas `DHCP` ones
are only accepted on the local network (connected to the same gateway as you).
All new rules will be limited to this local network.

It won't remember the network you're connected to until you change the default
ruleset. Once you do, it writes down an identifier for the network realm, 
together with the default ruleset plus the rule you added. Now when you connect 
to another network, it will put this identified ruleset aside, and try to find 
a ruleset for the new network. If it can't find any, it'll fallback to the 
default ruleset. When you connect to the identified network back, it will 
automagically bring back the rules you chose (magic here involves a network 
dispatcher telling it network changes).

The default ruleset also has a few basic stateful rules : accept icmp requests,
accept all from the localhost loop, accept already established connections, drop
invalid packets, and log anything dropped.


## What _not_ to expect

This firewall works on incoming traffic ; it won't be very useful on a server 
needing to forward anything. So basically, if your device is not a laptop you
use as a personal device, this software shouldn't be really fitted.

At the moment, you can't expect it to let any traffic come in from out of the 
local network realm either (excepted ssh, which is is a kind of "special" 
rule). At the moment, you can't either change the default ruleset on the 
command line ; you would have to manually edit /etc/servicewall/realms.json for 
that.


## Installation

### Dependencies

Required dependencies are `python 3`, `iptables`, `ulogd`, `systemd`, and either
`NetworkManager` or `systemd-networkd` enabled. If you run a linux on a laptop,
you should be all set.

There are python packages needed as well, but if you use a decent install 
method like `pip`, they should be managed all right. Those are :
- `python-iptables`
- `python-netifaces`
- `python-argparse`
- optional : `python-argcomplete`
- build-time : `python-setuptools`

You might really wish to have `python-argcomplete` for the command-line 
completion to work. This can really prove handy when you're looking for a 
service to allow.

### Install

Once you have the required dependencies, install the package with :

    # pip install servicewall

For those using Arch linux, there is a `PKGBUILD` for this into AUR, called
`servicewall-git`. Give it a try !

ServiceWall uses [ulogd](http://netfilter.org/projects/ulogd/index.html) to
dispatch the logs. It has its own dependent `servicewall-ulogd.service` that
gets pulled in automatically, don't try to run `ulogd.service` as it could cause
race problems between them.

## Usage

The firewall is disabled by default. To enable it, as root do `braise enable`,
or :

    # systemctl enable --now servicewall

You can suspend it with `systemctl stop servicewall` or

    # braise stop

(you indeed get the corresponding `disable` and `start` and `stop` options).
Note that ServiceWall starts before the nework target. At that point the
interfaces are not connected at all. It's acutally reloaded when the connection
is established to a realm. To have details on the status, use :

    # braise status

Once started, the default behaviour is to drop all that come in, excepted for
`ssh` from anywhere and `DHCP` from the local network. All that go out is
allowed. You can check the table of rules applied for the realm we're connected
to :

    # braise show table

ServiceWall works with service definitions provided by
[jhansonxi](https://www.blogger.com/profile/02954133518928245196). They link a
service to ports it needs. To allow a specific service, do :

    # braise allow service "Service Name"

which will add this service to this realm's definition. If you connect to
internet in another place, the rules for this place will be put aside, and 
brought back when you connect to it again. You can move back with
`braise disallow service ...`

Don't know what's the exact name of the service you want to allow ? You'll need
to :

    # braise show services

The list is quite long. Once you want exhaustive informations on a single 
service, do

    # braise show service "Service Name"

And if you wonder which services use to use port 80, do

    # braise show port 80

These rules are stored together with a string identifying the realm you're
connected to, in a dictionary called realm_defs. To interrogate it, do :

    # braise show realms

Particuliar attention was taken to logs. Logs are stored in systemd's
`servicewall-logs.service`. Journald takes care it can't fill the hard drive,
and that it's readable only to staff. Firewall logs are critical information,
and with this setup you can choose who has access. In Arch it's controlled with
an access list, you can view it with :

    # getfacl /var/log/journal

The firewall logs all that it drops. There's a log processor tool included ;
try it with

    # braise show logs

or

    # braise show logs -w since NUMBER_OF_SECONDS

The `-w|--with-names` option lets it show hostnames. This will let you see what
services queries were dropped. Now if the service name begins with a `<` it
means that it is the source that is operating the service, not the destination.
It might be a packet that iptables failed to recognize as belonging to an
established connection.

## Copyright

This software is copyrighted under the [GNU](http://www.gnu.org) Version 3 
license.

