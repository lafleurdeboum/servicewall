from os import scandir


def split_port_def(port_def):
    ports_list = []
    # In the worst case, port_def is "13:15,124,128/udp|120:122/tcp"
    # Which should mean 13 udp, 124 udp and range 120-122 tcp
    try:
        port_subdefs = port_def.split("|")
    except ValueError:
        port_subdefs = (port_def, )

    # first port_subdef is "13:15,124,128/udp"
    for port_subdef in port_subdefs:
        try:
            port_subdef, proto = port_subdef.split("/")
        except ValueError:
            # We have a port but no proto ; that's OK.
            # Empty proto means any of udp or tcp.
            proto = ""

        # first port_subdef is now "13:15,124,128" : proto is "udp"
        try:
            ports = port_subdef.split(",")
        except ValueError:
            ports = (port_subdef, )

        # ports is ("13:15", "124", "128")
        for port in ports:
            # port is a string ; let's check if this str is a number
            if port.isalnum():
                ports_list += ((int(port), proto), )
            else:
                # It's a port range, spelled ie "100:104".
                ports_start, ports_end = port.split(":")
                for port_range_item in range(int(ports_start), int(ports_end)+1):
                    ports_list += ((port_range_item, proto), )

    return tuple(ports_list)


def scan_service_definitions(definitions_dir):
    '''scan service definitions in the list given by jhansonxi'''
    # Files in the following dir define one or more protocols and
    # their portsi. Each file comes with the following format :
    #
    # [NAME_ONE]
    # title=EXPANDED NAME
    # description=BLA BLA BLA
    # categories=ONE;TWO;
    # reference=[HTTP://HTML_LINK LINK_NAME DESCRIPTION]
    # ports=220|3724,6112:6114,4000/tcp
    #
    # [NAME_TWO]
    # etc...

    filelist = scandir(definitions_dir)
    services = {}
    for filename in iter(filelist):
        print("processing %s" % filename.path)
        with open(filename.path, "r") as fd:
            # NAME_ONE and NAME_TWO are separated by a double newline
            service_list = fd.read().split("\n\n")
            for service in service_list:
                # _Some_ service descriptions finish in "\n\n"
                if service == "" or service == "\n":
                    continue
                service_desc = service.split("\n")
                service_name = service_desc[0].strip("[]")

                # get rid of empty strings :
                for i in range(service_desc.count("")):
                    service_desc.remove("")

                # services['NAME_ONE'] will return a dict with its parameters :
                services[service_name] = {
                    key: value for (key, value) in
                        ( item.split("=", 1) for item in iter(service_desc[1:]) )
                }
                port_def = split_port_def(services[service_name]["ports"])
                services[service_name]["ports"] = port_def

    return services


