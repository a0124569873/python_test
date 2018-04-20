Build usage
===========

Syntax::

	make FP_DIR=../fpn-6wind FPNSDK_DIR=../fpn-sdk [options]

Mandatory path variables:

	- ``FP_DIR``
	- ``FPNSDK_DIR``

Build options:

	- ``S`` to specify sources directory if not current one.
	- ``O`` to specifiy output directory (defaults to ``build/``).

Install options:

	- ``DESTDIR`` to specify install directory
	- ``prefix`` inside DESTDIR (defaults to ``/usr/local``)
	- ``exec_prefix`` (defaults to ``$(prefix)``)
	- ``libdir`` (defaults to ``$(exec_prefix)/lib``)
	- ``includedir`` (defaults to ``$(prefix)/include``)
	- ``bindir`` (defaults to ``$(prefix)/bin``)

Install commands:

	- ``install-target`` to install only library and test binary
	- ``install-devel`` to install all (with headers)
