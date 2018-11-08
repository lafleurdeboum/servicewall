from socket import socket, inet_ntoa, AF_INET, SOCK_DGRAM
from struct import pack
from fcntl import ioctl


def get_ip_address(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    return inet_ntoa(ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            pack("256s", bytes(ifname[:15], "utf-8"))
    )[20:24])

def get_netmask(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    return inet_ntoa(ioctl(
            s.fileno(),
            0x891b, # SIOCGIFNETMASK
            pack("256s", bytes(ifname[:15], "utf-8"))
    )[20:24])

def get_subnetwork(ifname):
    """return the IP address of the subnetwork slash the netmask, as in

            "192.168.1.0/255.255.255.0"
    """
    address = get_ip_address(ifname).split(".")
    netmask = get_netmask(ifname).split(".")
    subnetwork = [ str(int(int(address_block) * int(netmask_block) / 255))
            for address_block, netmask_block in zip(address, netmask) ]
    retval = "/".join((".".join(subnetwork), ".".join(netmask) ))
    return retval


# NOT WORKING - DEBUG NEEDED

def getHwAddr(ifname): # actually doesn't work, don't know why
    s = socket(AF_INET, SOCK_DGRAM)
    info = ioctl(
            s.fileno(),
            0x8927,
            pack("256s", bytes(ifname[:15], "utf-8"))
    )
    return ''.join(["%02x:" % ord(str(char)) for char in info[18:24]])[:-1]

