#!/usr/bin/env python
"""Install script for servicewall
"""


import setuptools
from setuptools.command.install import install
import os
from os import path, environ


class CustomInstallCommand(install):
    """Not in use anymore - the dispatcher link is made by braise enable.
    """
    def run(self):
        #for key, item in environ.items():
        #    print(key, item)
        install.run(self)


with open("README.md", "r") as fh:
    long_description = fh.read()

#   4 - Beta
#   5 - Production/Stable

here = path.abspath(path.dirname(__file__))
#for package in setuptools.find_packages(exclude=('scriptlets')):
for package in setuptools.find_packages():
    print("setuptools : including package %s" % package)

name="servicewall"
version = "0.3.3.3"

setuptools.setup(
    name=name,
    version=version,
    author="la Fleur",
    author_email="lafleur@boum.org",
    description="the desktop firewall that adapts to different network connections",
    keywords="dynamic adaptable iptables firewall",
    license="GNUv3",
    python_requires=">=3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://flip.local/~lafleur/servicewall",
    packages=setuptools.find_packages(),
    #packages=setuptools.find_packages(where="src"),
    classifiers=[
        'Development Status :: 3 - Alpha',
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
        "python-argcomplete",
    ],
    extras={
        "python-argcomplete": "have tab-completion in bash as root"
    },
    scripts=["servicewall/braise"],
    data_files=[
        ("/etc/servicewall", ["lib/realms.p"]),
        ("lib/servicewall", ["lib/services.p", "servicewall/toggler"]),
    ],
    #cmdclass={"install": CustomInstallCommand,},
)

