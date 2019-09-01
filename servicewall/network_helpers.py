"""Useful system calls to ask different things to the wireless controler.

"""

# Most of them use fnctl.ioctl to pack and unpack a request.

# some insights on packing an address :
# https://pymotw.com/2/socket/addressing.html

# For those taking an interface name iface as argument, see struct ifreq in
#     /usr/include/net/if.h
# we'll mimic ifreq with struct.pack("256s", bytes(ifname[:15], "utf-8"))
# details on constructing a C struct in python :
# https://docs.python.org/2/library/ctypes.html#arrays



import socket
import struct
import array
import fcntl


def get_all_interfaces():
    """Return a dict of interface names and their IPs.

    retrieved from http://code.activestate.com/recipes/439093/#c1
    """
    max_possible = 128  # Raise if needed.
    byte_number = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', b'\0' * byte_number)
    names_address = names.buffer_info()[0]
    outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', byte_number, names.buffer_info()[0])
    ))[0]
    namestr = names.tobytes()
    iface_list = []
    #ifaces = {}
    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split(b'\0', 1)[0]
        ip   = namestr[i+20:i+24]
        iface_list.append([ name.decode(), socket.inet_ntoa(ip) ])
        #ifaces[name.decode()] = socket.inet_ntoa(ip)
        # We don't care for the loopback interface :
    for index, iface in enumerate(iface_list):
        if iface[0] == "lo":
            del iface_list[index]
    return iface_list
    #ifaces.pop('lo')
    #return ifaces

def get_active_interface():
    """Return the name of the interface serving as gateway.
    """
    # AF_INET is a flag for ipv4 addressing.
    #return netifaces.gateways()[netifaces.AF_INET][0][1]
    return get_all_interfaces()[0][0]

def get_essid():
    """Return the ESSID for an interface, or None if we aren't connected.
    """
    try:
        interface = get_active_interface()
    except IndexError:
        #print("No active interface")
        return None
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
    try:
        fcntl.ioctl(
                s.fileno(),
                0x8b1b,   # SIOCGIWESSID, get essid
                request
        )
    except OSError as e:
        if e.errno == 95:       # Operation not supported
            #print("not connected")
            return None
    name = essid.tobytes().strip(b"\x00").decode()
    if name:
        return name
    else:
        return None

def get_realm_id():
    """Return a unique identifier for the Internet Service Provider
    """
    isp_id = get_essid()
    if not isp_id:      # Then the network probably isn't wifi. Check ethernet :
        import arpreq
        #isp_id = arpreq.arpreq(get_ip_address(get_active_interface()))
        isp_id = arpreq.arpreq(get_gateway_address())
    return isp_id

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", bytes(ifname[:15], "utf-8"))
    )[20:24])

def get_outside_ip_address(ifname):
    """DOESN'T WORK and I don't know what is this IP it's outputting"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8927, # SIOCGIFHWADDR
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
    """Return the ssid's MAC address as declared by the network controller.
    DEBUG Doesn't work with ethernet network providers though.
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

def get_mac_address(ip):
    """NOT WORKING - need to find how to mimic arpreq struct - clues in
    https://stackoverflow.com/questions/159137/getting-mac-address
    example of what's expected, written in C :
    https://stackoverflow.com/questions/11929556/how-to-get-the-mac-address-of-client-using-ioctl-function
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interface = get_active_interface()
    # SIOCGARP is documented in man 7 arp
    # and struct arpreq in /usr/include/net/if_arp.h .
    # It refers to struct sockaddr, defined in /usr/inlude/sys/socket.h .
    request = array.array("b")
    request.frombytes(
            interface.ljust(16, "\x00").encode()
    )
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8951, # SIOCGARP , mac address, according to man ioctl_list
            #0x8954, # SIOCGARP , mac address
            request
    )[20:24])

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
    """Read the default gateway directly from /proc.
    """
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            address = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        else:
            raise KeyError("No gateway found")
    return address

def get_gateway_hostname():
    return socket.getfqdn(get_gateway_address())

