NDP Proxy
=========

This software is an answer to the fact that the Linux kernel does not support to proxy NDP packets for a whole IPv6 range but only for a given set of addresses.

`ndp-proxy` listen to an interface, and when it receive an NDP Network Solicitation packet for an IPv6 in a given subnet, it will answer a Network Advertisement packet as if that IP was actually bound to the interface.
This allows to route a subnet through a machine acting as a router without having to configure a route to that machine on upstream routers. It is useful especially if upstream routers are managed by somebody else and cant be modified.

Usage
------
    /usr/sbin/ndp-proxy <options>

    Options:
     -h --help                              Display this help
     -i --interface <interface>             Sets the interface
     -m --netmask <netmask>                 Sets the netmask
     -n --network <network>                 Sets the network
     -p --pidfile <pidfile>                 Sets the pidfile
     -d --daemon                            Daemon mode
     -v --verbose                           Verbose mode
     -q --quiet                             Quiet mode

Build
------
    make && make install

An init script can also be installed with :

    make install-init

Options can then be set in `/etc/sysconfig/ndp-proxy` or `/etc/default/ndp-proxy` like this :

    OPTIONS="-i eth0 -n ::1 -d"
