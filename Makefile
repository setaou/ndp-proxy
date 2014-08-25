#.SILENT:

main: ndp-proxy

install: /usr/sbin/ndp-proxy

install-init: /etc/init.d/ndp-proxy

/etc/init.d/ndp-proxy: ndp-proxy-init
	install -o root -g root -m 744 ndp-proxy-init /etc/init.d/ndp-proxy

/usr/sbin/ndp-proxy: ndp-proxy
	install -o root -g root -m 744 ndp-proxy /usr/sbin/ndp-proxy

ndp-proxy: ndp-proxy.c
	gcc ndp-proxy.c -o ndp-proxy

