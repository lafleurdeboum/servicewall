# Making this directory a python package.
name = "servicewall"
__all__ = [
    "service_helpers",
    "network_helpers",
    "servicewall",
    "statefulfirewall",
    "firewall",
]
#from pkgutil import extend_path
#__path__ = extend_path(__path__, __name__)

# Load the main package
from servicewall.servicewall import ServiceWall

