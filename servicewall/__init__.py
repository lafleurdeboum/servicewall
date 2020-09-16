"""This is ServiceWall's package definition. See main.py for real content.
"""
import os
import pickle
#from pkgutil import extend_path
#__path__ = extend_path(__path__, __name__)
from servicewall.main import ServiceWall
# update_service_defs needs to have service_helpers imported
# to have working pickle in the ServiceWall class.
from servicewall import service_helpers


# Making this directory a python package.
name = "servicewall"
__all__ = [
    "service_helpers",
    "network_helpers",
    "main",
    "statefulfirewall",
    "firewall",
]

def update_service_defs():
    service_pickle = "lib/services.p"
    service_defs_dir = "/etc/gufw/app_profiles"
    service = service_helpers.scan_service_definitions(service_defs_dir)
    print("writing defs from %s to %s" % (service_defs_dir, service_pickle))
    if os.path.isfile(service_pickle):
        raise SystemError("There's already a file named %s" % service_pickle)
    with open(service_pickle, "wb") as fd:
        pickle.dump(service, fd)

