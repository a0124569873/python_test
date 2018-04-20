Usage
=====

To use Linux synchronization, start the |cmgr| and the |fpm|:

.. code-block:: console

   # modprobe ifuid
   # modprobe fptun
   # modprobe nf_conntrack_netlink
   # fpmd
   # cmgrd

.. rubric:: Example

#. Set up a |nat| rule under Linux:

   .. code-block:: console

      # echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
      # echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal
      # ip link set eth1 up
      # ip link set eth2 up
      # ip ad ad 2.0.0.1/24 dev eth1
      # ip ad ad 2.1.0.1/24 dev eth2
      # ip route add 100.2.2.1/32 via 2.0.0.5
      # ip route add 110.2.2.1/32 via 2.1.0.5
      # iptables -P INPUT ACCEPT
      # iptables -P FORWARD ACCEPT
      # iptables -P OUTPUT ACCEPT
      # iptables -t nat -F
      # iptables -t nat -A POSTROUTING -s 100.0.0.0/8 -o eth2 -j SNAT --to-source 2.1.0.1
      # iptables -nL -t nat
        Chain PREROUTING (policy ACCEPT)
        target     prot opt source               destination

        Chain POSTROUTING (policy ACCEPT)
        target     prot opt source               destination
        SNAT       all  --  100.0.0.0/8          0.0.0.0/0           to:2.1.0.1

        Chain OUTPUT (policy ACCEPT)
        target     prot opt source               destination

#. Launch the *fp-cli* module and check |fp| statistics:

   .. code-block:: console

      # fp-cli

   .. code-block:: fp-cli

      <fp-0> dump-nftable 4 nat alNumber of flows: 1/1024
      Flow: #0 - uid #00000000
           Proto: 6
           Original: src: 100.2.2.1:6050 -> dst: 110.2.2.1:6050
           Reply:    src: 110.2.2.1:6050 -> dst: 2.1.0.1:6050
           VRF-ID: 0
           Flag: 0x95, update: no, snat: yes, dnat: no,
                       assured: yes, end: yes
           Stats:
                   Original: pkt: 20, bytes: 6160
                   Reply:    pkt: 11, bytes: 5692

The |nat| rule is correctly implemented on the |fp|.

NAT management
--------------

nf-nat-conntrack
~~~~~~~~~~~~~~~~

.. rubric:: Description

Show, enable or disable the Netfilter cache in the |fp|.

.. rubric:: Synopsis

.. code-block:: fp-cli

   nf-nat-conntrack [<on|off>]

.. rubric:: Parameters

No parameter
   Display the status of the Netfilter cache in the |fp|, set to *on* by
   default.
on|off
   Enable or disable the Netfilter cache in the |fp|.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> nf-nat-conntrack
   nf-nat-conntrack is on
