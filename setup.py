from setuptools import find_packages, setup

setup(
    name="Bluewall",
    version="1.0",
    platforms=["any"],
    long_description='Firewall configuration generator and implementor for Cyber Network Defenders. ',
    packages=find_packages(),
    scripts=['bin/bluewall', 'bin/bs'],
    author="Austin Taylor, Nicholas Lupien",
    author_email="git@austin-taylor.io, nick.lupien@infiniteloops.net"

)
