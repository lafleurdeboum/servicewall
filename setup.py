import setuptools
from os import path

with open("README.md", "r") as fh:
    long_description = fh.read()

#   4 - Beta
#   5 - Production/Stable

here = path.abspath(path.dirname(__file__))

setuptools.setup(
    name="servicewall",
    version="0.3",
    author="la Fleur",
    author_email="lafleur@boum.org",
    description="the desktop firewall that adapts to different network connections",
    keywords="dynamic adaptable iptables firewall",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/servicewall",
    packages=setuptools.find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL License",
        "Operating System :: OS Independent",
    ],
    install_requires=["python-iptables"],
    scripts=["servicewall/braise"],
    data_files=[
        ("/var/lib/servicewall", ["var/realms.p", "var/services.p"]),
    ],
)
