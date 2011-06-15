#!/usr/bin/env python

from setuptools import setup

setup(
    name="VNCAuthProxy",
    version="0.9",
    packages=[
        "twisted.plugins",
        "vncap",
    ],
    install_requires=[
        "Twisted>=10.2.0",
    ],
    author="Corbin Simpson",
    author_email="simpsoco@osuosl.org",
    description="A Twisted-based VNC proxy",
    license="GPL2",
    url="http://code.osuosl.org/projects/twisted-vncauthproxy",
)

# Regenerate Twisted plugin cache.
try:
    from twisted.plugin import getPlugins, IPlugin
    list(getPlugins(IPlugin))
except:
    pass
