#!/usr/bin/env python
"""Install script for servicewall
"""


import sys
import stat
from os import path, chmod, popen
from distutils import log
import setuptools
from setuptools.command.install import install


class CustomInstall(install):
    """Only let user write and group read files in /etc/servicewall"""
    def run(self):
        mode = stat.S_IWRITE + stat.S_IREAD + stat.S_IRGRP
        dirmode = stat.S_IWRITE + stat.S_IREAD + stat.S_IXUSR + stat.S_IRGRP + stat.S_IXGRP
        install.run(self)
        for filepath in self.get_outputs():
            if "/etc/servicewall" in filepath:
                log.info("setting %s to mode %s" % (filepath, oct(mode)[2:]))
                dirpath = path.split(filepath)[0]
                chmod(filepath, mode)
                chmod(dirpath, dirmode)


with open("README.md", "r") as fd:
    long_description = fd.read()

NAME = "servicewall"
#version = "0.4.3"
version = popen("git tag | tail -n 1").read().strip()
here = path.abspath(path.dirname(__file__))

for package in setuptools.find_packages():
    print("setuptools : including package %s" % package, file=sys.stderr)

setuptools.setup(
    name=NAME,
    version=version,
    author="la Fleur",
    author_email="lafleur@boum.org",
    description="The desktop firewall that remembers the different network you connect to.",
    keywords="dynamic adaptable iptables firewall",
    license="GNUv3",
    python_requires=">=3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lafleurdeboum/servicewall",
    packages=setuptools.find_packages(),
    #packages=setuptools.find_packages(where="src"),
    classifiers=[
        'Development Status :: 4 - Beta',
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        #"Operating System :: OS Independent",
        "Operating System :: POSIX",   # We need iptables.
    ],
    install_requires=[
        "argparse",
        "arpreq",
        "python-iptables",
        "python-systemd",
    ],
    extras_require={
        "argument completion as root": "argcomplete",
    },
    scripts=[
        "servicewall/braise",
    ],
    data_files=[
        ("/etc/systemd/system", [
            "etc/systemd/servicewall-ulogd.service",
            "etc/systemd/servicewall-logs.service",
            "etc/systemd/servicewall-logs.socket",
            "etc/systemd/servicewall.service",
        ]),
        ("/etc/servicewall/", [
            "etc/servicewall/realms.json",
            "etc/servicewall/ulogd.conf",
        ]),
        ("/etc/servicewall/services", [
            "etc/servicewall/services/.keepme",
        ]),
        ("/etc/xdg/autostart/", [
            "lib/servicewall-systray.desktop",
        ]),
        ("lib/servicewall/", [
            "lib/systray.py",
            "lib/services.p",
            "lib/toggler",
            "lib/icon.png",
            "lib/icon2.png",
        ]),
    ],
    cmdclass={"install": CustomInstall},
)

