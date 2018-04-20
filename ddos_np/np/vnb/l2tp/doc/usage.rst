Usage
=====

L2TP support in |vnb| is active by
default as long as the |vnb-l2tp| module is detected.

To avoid loading the |vnb-l2tp| module, specify only the VNB modules you want to
load in the MODULES variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

.. code-block:: console

   : ${MODULES:=ether ppp pppoe}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

L2TP nodes usage
----------------

L2TP nodes can be managed manually with a tool like `ngctl`, or, more
frequently, through a userland daemon (for instance: MPD), with a basic setup
definition and dynamic nodes management.

.. seealso::

   For more information on how to configure MPD, see the relevant documentation.
