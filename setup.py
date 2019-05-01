#!/usr/bin/env python
"""Install script for servicewall
"""


import setuptools
from setuptools.command.install import install
import sys
from os import path, environ


class CustomInstallCommand(install):
    """Not in use anymore - the dispatcher link is made by braise enable.
    """
    def run(self):
        #print("setup.py - running install with environ :")
        #for key, item in environ.items():
        #    print(key, item)
        install.run(self)


with open("README.md", "r") as fh:
    long_description = fh.read()

here = path.abspath(path.dirname(__file__))
for package in setuptools.find_packages():
    print("setuptools : including package %s" % package, file=sys.stderr)

name="servicewall"
version = "0.4.2"

setuptools.setup(
    name=name,
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
        "python-iptables",
        "python-argparse",
        "python-netifaces",
        "python-systemd",
        "python-arpreq",
    ],
    extras_require={
        "argument completion as root": "python-argcomplete",
    },
    scripts=[
                "servicewall/braise",
    ],
    data_files=[
        ("/etc/servicewall", ["etc/realms.json", "etc/config.json"]),
        ("/etc/xdg/autostart", ["lib/servicewall-systray.desktop"]),
        ("lib/servicewall", [
                "lib/systray.py",
                "lib/services.p",
                "lib/toggler",
                "lib/icon.png",
                "lib/icon2.png",
        ]),
    ],
    cmdclass={"install": CustomInstallCommand,},
)

