from os import scandir
from collections import namedtuple

PortDef = namedtuple("PortDef", "udp tcp")
ServiceDef = namedtuple("ServiceDef", "title description ports categories reference")

def split_port_def(port_def):
    ports_dict = {"udp": [], "tcp": []}

    # In the worst case, port_def is "13:15,124/udp|120:122"
    # Which should mean 13 to 15 and 124, all udp, and 120 to 122 both udp and tcp
    try:
        proto_subdefs = port_def.split("|")
    except ValueError:
        proto_subdefs = (port_def, )

    # first port_subdef is "13:15,124,128/udp"
    for proto_subdef in proto_subdefs:
        try:
            port_subdef, proto_def = proto_subdef.split("/")
            if proto_def == "tcp6":
                protos = ("tcp", )
                print("  WARNING : using tcp for tcp6")
            else:
                protos = (proto_def, )
        except ValueError:
            port_subdef = proto_subdef
            protos = ("udp", "tcp")

        # first port_subdef is now "13:15,124,128" : protos is ("udp", )
        try:
            port_list = port_subdef.split(",")
        except ValueError:
            port_list = [ port_subdef ]

        # port_list is ("13:15", "124", "128"). Port ranges can be very wide,
        # yielding 10000 entries. We'll keep them as ranges.
        for proto in protos:
            for port in port_list:
                ports_dict[proto].append(port)

    return PortDef(ports_dict["udp"], ports_dict["tcp"])


def scan_service_definitions(definitions_dir):
    '''scan service definitions in the list given by jhansonxi'''
    # Files in the definitions dir define one or more protocols and
    # their ports. Each file comes with the following format :
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
                print("  -> %s" % service_name)

                # get rid of empty strings :
                for i in range(service_desc.count("")):
                    service_desc.remove("")

                # services['NAME_ONE'] will return a dict with its parameters :
                service_def = {
                    key: value for (key, value) in
                        ( item.split("=", 1) for item in iter(service_desc[1:]) )
                }
                if not "reference" in service_def:
                    service_def["reference"] = ""
                service_def["ports"] = split_port_def(service_def["ports"])
                s = ServiceDef(
                        service_def["title"],
                        service_def["description"],
                        service_def["ports"],
                        service_def["categories"],
                        service_def["reference"],
                )
                services[service_name] = s

    return services

