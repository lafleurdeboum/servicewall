# ServiceWall

## Target audience

You have a personal device that you use as a client. You already know that some
services need to use ports on the network card, such as Skype, MORPGames, or
sharing files with someone using Samba, local games ...

And you run a linux kernel and Network Manager.

You want a firewall that drops invalid traffic whatsoever, and allows "some"
services at home for people at home, and usually less when you're in a ...
random place.

This firewall adapts to the changes in the connection provider's declared name
(the ESSID), using a set of rules for each of these realms. It stores the list
of allowed services for each ESSID it meets in a dictionary, starting with a
customisable default, adding the services you tell it to.

## Installation

### Dependencies

This software needs the `python 3`, `iptables`, `python-iptables` and
`python-netifaces` packages to manage its very basic iptables rules. It relies as
well on `python-argparse` to parse the cmdline arguments. Finally, you will need
`python-setuptools` to install it using the provided `setup.py`.

It will also need your computer to run `NetworkManager` or `systemd-networkd`,
because it needs a network dispatcher to trigger connectivity change events.
Any network event dispatcher would do, it just needs to call the script called
`toggler` in the `lib` directory (`setup.py` would install it in
`$PREFIX/lib/servicewall/`).

You might also wish to have `python-argcomplete` for the command-line completion to 
work. This can really prove handy when you're looking for a service to allow.

### Install

You could very simply install the package with :

    # ./setup.py install

For those using Arch linux, there is a PKGBUILD script for this, but at the moment
it's not uploaded. Coming soon ! There also is a pip package, but it's quite outdated
at the moment.

## Usage

The firewall is disabled by default. To enable it now _and at boot-time_ :

    # braise enable

(you indeed get the corresponding `disable`). Once started, the default behaviour is
to drop all that come in, excepted for some very common and useful services (details
on this TODO). All that go out is allowed.

To have details on the status, use :

    # braise status

To allow a specific service, do :

    # braise add "Service Name"

which will add this service to this realm's definition. If you connect to
internet in another place, the rules for this place (identified by the ESSID of
the connection) will be put aside, and brought back when you connect to it
again. All this supports completion with `python-argcomplete`, so make shure you have
it !

Don't know what's the exact name of the service you want to allow ? You'll need to :

    # braise show services

The list is quite long. Once you want exhaustive informations on a single service, do

    # braise show service "Service Name"

These rules are stored in a dictionary called realm_defs. To interrogate it, do :

    # braise show realms

And in the end, the firewall logs all that it drops ; there's a log processor
tool included ; try it with

    # braise show logs

or

    # braise show logs since NUMBER_OF_SECONDS


This software is copyrighted under the [GNU](http://www.gnu.org) Version 3 license.

