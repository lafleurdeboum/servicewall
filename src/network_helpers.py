"""Useful system calls to ask different things to the wireless controler.
"""


import socket
import struct
import array
import fcntl
import netifaces


def get_active_interface():
    """Return the name of the interface serving as gateway.
    """
    # AF_INET is a flag for ipv4 addressing
    return netifaces.gateways()[netifaces.AF_INET][0][1]

def get_essid():
    """Return the ESSID for an interface, or None if we aren't connected.
    """
    interface = get_active_interface()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # The payload for this call is formatted to 32 double hexadecimal ints.
    essid = array.array("b", b"\x00" * 32)
    essidPointer, essidLength = essid.buffer_info()
    request = array.array("b")
    request.frombytes(
            # The interface name is formatted to 16 double hexadecimal ints.
            interface.ljust(16, "\x00").encode()
            + struct.pack("PHH", essidPointer, essidLength, 0)
    )
    fcntl.ioctl(
            s.fileno(),
            0x8b1b,   # SIOCGIWESSID, get essid
            request)
    name = essid.tobytes().strip(b"\x00").decode()
    if name:
        return name
    return None

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", bytes(ifname[:15], "utf-8"))
    )[20:24])

def get_netmask(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x891b, # SIOCGIFNETMASK
            struct.pack("256s", bytes(ifname[:15], "utf-8"))
    )[20:24])


def get_subnetwork():
    """return the IP address of the subnetwork slash the netmask, as in

            "192.168.1.0/255.255.255.0"
    """
    interface = get_active_interface()
    address = get_ip_address(interface).split(".")
    netmask = get_netmask(interface).split(".")
    subnetwork = [ str(int(int(address_block) * int(netmask_block) / 255))
            for address_block, netmask_block in zip(address, netmask) ]
    return "/".join((".".join(subnetwork), ".".join(netmask) ))

def get_essid_mac_address(ifname):
    """Return the ssid's MAC address as declared by the network controller
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = fcntl.ioctl(
            s.fileno(),
            0x8b15, # SIOCGIWAP , mac address
            struct.pack("265s", bytes(ifname[:15], "utf-8"))
    )
    # From internet talk : SSID is encoded after a \x01\x00 keycode.
    index = payload.index(b"\x01\x00") + 2
    # From convention : MAC addressing is 6 hexadecimal double ints.
    address = payload[index:index+6].hex()
    return ":".join([ address[i:i+2] for i in range(0, 12, 2) ])

def get_essid_alt(ifname):
    from subprocess import Popen, PIPE
    process = Popen(["iw", ifname, "info"], stdout=PIPE)
    stdout, stderr = process.communicate()
    try:
        endstring = stdout[stdout.index(b"ssid ") + 5:]
    except ValueError:
        raise SystemExit("Interface %s not found" % ifname)
    ssid = endstring.split(b"\n")[0]
    return ssid.decode()

def get_gateway_address():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def get_gateway_hostname():
    return socket.getfqdn(get_gateway_address())



