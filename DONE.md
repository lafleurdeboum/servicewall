### sept. 2020

- support for additional service defs
- braise add service --in-default-profile : the rule is applied in any realm.
- braise add service --globally : the client can come from anywhere in the net.
- XTABLES_LIBDIR doesn't get set ; workaround proposed is to set it
  in `/etc/environment`. This is arguable since this file is not a global
  conf file (see https://unix.stackexchange.com/questions/473001/env-vars-in-etc-environment-not-globally-visible ).

### winter 2020
- braise show logs : propose to see hostnames as `braise show logs --with-hostnames`
- have port ranges in services.p->service->ports because some have thousands, making the pickle huge.
- use realms.p [and services.p ?] as a template, instanciate in /etc/servicewall

