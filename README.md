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
needing to forward anything.

At the moment, you can't expect it to let any traffic come in from out of the 
local network realm either (excepted ssh, which is is a kind of "special" 
rule). At the moment, you can't either change the default ruleset on the 
command line ; you would have to manually edit /etc/servicewall/realms.json for 
that.

So basically, if your device is not a laptop you use as a personal device, this
software shouldn't be really fitted.


## Installation

### Dependencies

This software needs the `python 3`, `iptables`, `python-iptables` and
`python-netifaces` packages to manage its very basic iptables rules. It relies 
as well on `python-argparse` to parse the cmdline arguments. Finally, you will 
need `python-setuptools` to install it using the provided `setup.py`.

It will also need your computer to run `NetworkManager` or `systemd-networkd`,
because it needs a network dispatcher to trigger connectivity change events.
Any network event dispatcher would do, it just needs to call the script called
`toggler` in the `lib` directory (`setup.py` would install it in
`$PREFIX/lib/servicewall/`).

You might also wish to have `python-argcomplete` for the command-line 
completion to work. This can really prove handy when you're looking for a 
service to allow.

### Install

You could very simply install the package with :

    # ./setup.py install

For those using Arch linux, there is a PKGBUILD script for this, but at the 
moment it's not uploaded. Coming soon ! There also is a pip package, but it's 
quite outdated at the moment.


## Usage

The firewall is disabled by default. To enable it now _and at boot-time_ :

    # braise enable

(you indeed get the corresponding `disable`). Once started, the default 
behaviour is to drop all that come in, excepted for `ssh` from anywhere and 
`DHCP` from the local network. All that go out is allowed.

To have details on the status, use :

    # braise status

ServiceWall works with service definitions provided by [jhansonxi](https://www.blogger.com/profile/02954133518928245196). They link a service to ports it 
needs. To allow a specific service, do :

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

These rules are stored together with a string identifying the network you're
connected to, in a dictionary called realm_defs. To interrogate it, do :

    # braise show realms

And in the end, the firewall logs all that it drops ; there's a log processor
tool included ; try it with

    # braise show logs

or

    # braise show logs since NUMBER_OF_SECONDS


## Copyright

This software is copyrighted under the [GNU](http://www.gnu.org) Version 3 
license.

