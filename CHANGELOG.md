# Revisions history

  - 0.4.5
    - support for additional service defs in `/etc/servicewall/services`
    - `braise add service --in-default-profile` : the rule is applied in any realm
    - `braise add service --globally` : the client can come from anywhere in the net
    - XTABLES_LIBDIR doesn't get set ; workaround proposed is to set it
      in `/etc/environment`. This is arguable since this file is not a global
      conf file - see [this stackexchange thread](https://unix.stackexchange.com/questions/473001/env-vars-in-etc-environment-not-globally-visible)

  - 0.4.4
    - `braise show logs --with-hostnames` option
    - have port ranges in services.p->service->ports because some have thousands
    - use realms.p [and services.p ?] as a template, instanciate in /etc/servicewall

  - 0.4.3    switch to ulogd ; remove dependency on netifaces ; new GUI draft
  - 0.4.2    `braise add` becomes `braise allow`
  - 0.4.1    use ioctls to get IP, MAC and ESSID ; GUI draft
  - 0.3.8    logs can tell services asked for
  - 0.3.7    `/etc/servicewall/realms.json` saves profiles for realms
  - 0.3.6    added offline mode
  - 0.3.5    various bugfixes
  - 0.3.4    `braise show port` lists services by port
  - 0.3.3    service_defs pickle uses namedtuple
  - 0.3.2    networkd-dispatcher support
  - 0.3      Object Oriented rewrite
  - 0.2      alpha release - basic functionality
