#!/usr/bin/env python

from setuptools import setup

setup(
    name="VNCAuthProxy",
    version="1.2.0",
    python_requires='<3.0',
    packages=[
        "twisted.plugins",
        "vncap",
        "vncap.vnc",
        "vncap.ssh"
    ],
    install_requires=[
        "Twisted>=10.2.0,<20.4.0",
        "txWS==0.9.1",
        "pyopenssl<22.0.0",
        # Set ceilings which still support python2 for dependencies
        "cryptography<3.4",
        "idna<3.0",
        "pyasn1",
        "PyHamcrest<2.0",
        "service-identity",
        "typing<3.10",
    ],
    author="Corbin Simpson, OSU Open Source Lab",
    author_email="simpsoco@osuosl.org, pypi@osuosl.org",
    description="A Twisted-based VNC proxy",
    license="GPL2",
    url="https://github.com/osuosl/twisted_vncauthproxy",
)

# Regenerate Twisted plugin cache.
try:
    from twisted.plugin import getPlugins, IPlugin
    list(getPlugins(IPlugin))
except:
    pass
