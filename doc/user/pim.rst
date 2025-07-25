.. _pim:

***
PIM
***

PIM -- Protocol Independent Multicast

*pimd* supports PIM-SM as well as IGMP v2 and v3. PIM is
VRF aware and can work within the context of VRFs in order to
do S,G mrouting. Additionally, PIM can be used in the EVPN underlay
network for optimizing forwarding of overlay BUM traffic.

.. note::

   On Linux for PIM-SM operation you *must* have kernel version 4.19 or greater.
   To use PIM for EVPN BUM forwarding, kernels 5.0 or greater are required.
   OpenBSD has no multicast support and FreeBSD, and NetBSD only
   have support for SSM.

.. _starting-and-stopping-pimd:

Starting and Stopping pimd
==========================

.. include:: config-include.rst

If starting daemons by hand then please note, *pimd* requires zebra for proper
operation. Additionally *pimd* depends on routing properly setup and working in
the network that it is working on.

::

   # zebra -d
   # pimd -d


Please note that *zebra* must be invoked before *pimd*.

To stop *pimd* please use::

   kill `cat /var/run/frr/pimd.pid`

Certain signals have special meanings to *pimd*.

+---------+---------------------------------------------------------------------+
| Signal  | Meaning                                                             |
+=========+=====================================================================+
| SIGUSR1 | Rotate the *pimd* logfile                                           |
+---------+---------------------------------------------------------------------+
| SIGINT  | *pimd* sweeps all installed PIM mroutes then terminates gracefully. |
| SIGTERM |                                                                     |
+---------+---------------------------------------------------------------------+

*pimd* invocation options. Common options that can be specified
(:ref:`common-invocation-options`).

PIM Routers
-----------

.. clicmd:: router pim [vrf NAME]

   Configure global PIM protocol

.. clicmd:: rp A.B.C.D A.B.C.D/M

   In order to use pim, it is necessary to configure a RP for join messages to
   be sent to. Currently the only methodology to do this is via static rp
   commands. All routers in the pim network must agree on these values. The
   first ip address is the RP's address and the second value is the matching
   prefix of group ranges covered. This command is vrf aware, to configure for
   a vrf, specify the vrf in the router pim block.

.. clicmd:: no autorp discovery

   In order to use pim, it is necessary to configure a RP for join messages to
   be sent to. FRR supports learning RP information dynamically via the AutoRP
   protocol and performs discovery by default. This command will disable the
   AutoRP discovery protocol.
   All routers in the pim network must agree on the network RP information, so
   all routers in the network should have AutoRP either enabled or disabled.
   This command is vrf aware, to configure for a vrf, specify the vrf in the
   router pim block.

.. clicmd:: autorp announce A.B.C.D [A.B.C.D/M | group-list PREFIX_LIST]

   Configure the router to advertise itself as a candidate PIM-SM RP via AutoRP.
   The supported groups can be defined as a single group range, or multiple
   group ranges can be defined via a prefix list.

.. clicmd:: autorp announce {scope (1-255) | interval (1-65535) | holdtime (0-65535)}

   Configure the AutoRP advertise messages. The scope defines the TTL value in the
   messages to limit the scope, defaults to 31. Interval defines the number of
   seconds elapsed between advertise messages sent, defaults to 60. Hold time defines
   how long the AutoRP mapping agent will consider the information valid, setting to
   0 will disable expiration of the candidate RP information, defaults to 3 * interval.

.. clicmd:: rp keep-alive-timer (1-65535)

   Modify the time out value for a S,G flow from 1-65535 seconds at RP.
   The normal keepalive period for the KAT(S,G) defaults to 210 seconds.
   However, at the RP, the keepalive period must be at least the
   Register_Suppression_Time, or the RP may time out the (S,G) state
   before the next Null-Register arrives. Thus, the KAT(S,G) is set to
   max(Keepalive_Period, RP_Keepalive_Period) when a Register-Stop is sent.
   If choosing a value below 31 seconds be aware that some hardware platforms
   cannot see data flowing in better than 30 second chunks. This command is
   vrf aware, to configure for a vrf, specify the vrf in the router pim block.

.. clicmd:: bsr candidate-bsr [priority (0-255)] [source [address A.B.C.D] | [interface INTERFACE] | [loopback] | [any]]

   Configure the router to advertise itself as a candidate PIM-SM BSR. The candidate
   with the highest priority becomes the BSR for the domain (high wins). When priority is the
   same for more than one candidate BSR, the candidate with the highest IP address
   becomes the BSR of the domain. The address can be configured explicitly
   via ``address``, or be selecting an interface name using ``interface``.
   If ``any`` is configured the highest address from any interface will be selected.
   By default, the highest loopback address is selected, which can also be
   configured via ``loopback``

.. clicmd:: bsr candidate-rp [interval]

   Configure the router to advertise itself as a candidate PIM-SM RP at the
   specified ``interval`` in seconds.


.. clicmd:: bsr candidate-rp group A.B.C.D/M

   Configure the multicast group prefix that this candidate RP advertises itself for.
   This command can be repeated for all desired groups that need to be added to the
   candidate RP advertisement.

.. clicmd:: bsr candidate-rp [priority (0-255)] [source [address A.B.C.D] | [interface INTERFACE] | [loopback] | [any]]

   Configure the router to advertise itself as a candidate PIM-SM RP. ``interval``
   can be used to configure the interval in seconds to send these advertisements.
   The candidate with the lowest priority becomes the RP for the domain (low wins).
   When priority is the same for more than one candidate RP, the candidate with
   the highest IP address becomes the BSR of the domain. The address can be
   configured explicitly via ``address``, or be selecting an interface name
   using ``interface``. If ``any`` is configured the highest address from any
   interface will be selected.By default, the highest loopback address is
   selected, which can also be configured via ``loopback``.

.. clicmd:: register-accept-list PLIST

   When pim receives a register packet the source of the packet will be compared
   to the prefix-list specified, PLIST, and if a permit is received normal
   processing continues.  If a deny is returned for the source address of the
   register packet a register stop message is sent to the source.

.. clicmd:: spt-switchover infinity-and-beyond [prefix-list PLIST]

   On the last hop router if it is desired to not switch over to the SPT tree
   configure this command. Optional parameter prefix-list can be use to control
   which groups to switch or not switch. If a group is PERMIT as per the
   PLIST, then the SPT switchover does not happen for it and if it is DENY,
   then the SPT switchover happens.
   This command is vrf aware, to configure for a vrf, specify the vrf in the
   router pim block.

.. clicmd:: ecmp

   If pim has the a choice of ECMP nexthops for a particular RPF, pim will
   cause S,G flows to be spread out amongst the nexthops. If this command is
   not specified then the first nexthop found will be used. This command is vrf
   aware, to configure for a vrf, specify the vrf in the router pim block.

.. clicmd:: ecmp rebalance

   If pim is using ECMP and an interface goes down, cause pim to rebalance all
   S,G flows across the remaining nexthops. If this command is not configured
   pim only modifies those S,G flows that were using the interface that went
   down. This command is vrf aware, to configure for a vrf, specify the vrf in
   the router pim block.

.. clicmd:: join-prune-interval (1-65535)

   Modify the join/prune interval that pim uses to the new value. Time is
   specified in seconds. This command is vrf aware, to configure for a vrf,
   enter the vrf submode.  The default time is 60 seconds.  If you enter
   a value smaller than 60 seconds be aware that this can and will affect
   convergence at scale.

.. clicmd:: keep-alive-timer (1-65535)

   Modify the time out value for a S,G flow from 1-65535 seconds. If choosing
   a value below 31 seconds be aware that some hardware platforms cannot see data
   flowing in better than 30 second chunks. This command is vrf aware, to
   configure for a vrf, specify the vrf in the router pim block.

.. clicmd:: packets (1-255)

   When processing packets from a neighbor process the number of packets
   incoming at one time before moving on to the next task. The default value is
   3 packets.  This command is only useful at scale when you can possibly have
   a large number of pim control packets flowing. This command is vrf aware, to
   configure for a vrf, specify the vrf in the router pim block.

.. clicmd:: register-suppress-time (1-65535)

   Modify the time that pim will register suppress a FHR will send register
   notifications to the kernel. This command is vrf aware, to configure for a
   vrf, specify the vrf in the router pim block.

.. clicmd:: send-v6-secondary

   When sending pim hello packets tell pim to send any v6 secondary addresses
   on the interface. This information is used to allow pim to use v6 nexthops
   in it's decision for RPF lookup. This command is vrf aware, to configure for
   a vrf, specify the vrf in the router pim block.

.. clicmd:: ssm prefix-list WORD

   Specify a range of group addresses via a prefix-list that forces pim to
   never do SM over. This command is vrf aware, to configure for a vrf, specify
   the vrf in the router pim block.

.. clicmd:: rpf-lookup-mode MODE [group-list PREFIX_LIST] [source-list PREFIX_LIST]

   MODE sets the method used to perform RPF lookups. Supported modes:

   urib-only
      Performs the lookup on the Unicast RIB. The Multicast RIB is never used.

   mrib-only
      Performs the lookup on the Multicast RIB. The Unicast RIB is never used.

   mrib-then-urib
      Tries to perform the lookup on the Multicast RIB. If any route is found,
      that route is used. Otherwise, the Unicast RIB is tried.

   lower-distance
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the lower administrative distance is used;  if they're equal, the
      Multicast RIB takes precedence.

   longer-prefix
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the longer prefix length is used;  if they're equal, the
      Multicast RIB takes precedence.

      The ``mrib-then-urib`` setting is the default behavior if nothing is
      configured. If this is the desired behavior, it should be explicitly
      configured to make the configuration immune against possible changes in
      what the default behavior is.

   If a group and/or source prefix list is provided, then the RPF lookup mode
   will only apply to source, group addresses that match the given prefix list(s).
   Not all RPF lookups have a valid group address when performing a lookup, e.g. RPF
   to an RP only does a lookup to the RP address and has no specific group.
   Lookups that do not have a specific group will only use lookup modes that do not
   specify a group-list.
   A global rpf lookup mode that does not have a group or source list is always installed
   and, as documented above, uses the ``mrib-then-urib`` mode by default.
   This can be changed with an rpf-lookup-mode MODE that does not specify group or source lists.
   There can be any number of rpf lookup modes, as long as the combination of group and source
   list is unique.

.. warning::

   Unreachable routes do not receive special treatment and do not cause
   fallback to a second lookup.

.. _pim-global-configuration:

Global Multicast
================

These commands are valid at the top-level of the configuration (or also per
vrf where indicated), instead of under the 'router pim' submode.

.. clicmd:: ip igmp generate-query-once [version (2-3)]

   Generate IGMP query (v2/v3) on user requirement. This will not depend on
   the existing IGMP general query timer.If no version is provided in the cli,
   the default will be the igmp version enabled on that interface.

.. clicmd:: ip igmp watermark-warn (1-65535)

   Configure watermark warning generation for an igmp group limit. Generates
   warning once the configured group limit is reached while adding new groups.
   'no' form of the command disables the warning generation. This command is
   vrf aware. To configure per vrf, enter vrf submode.


.. _pim-multicast-rib:

Multicast RIB Commands
----------------------

The Multicast RIB provides a separate table of unicast destinations which
is used for Multicast Reverse Path Forwarding decisions. It is used with
a multicast source's IP address, hence contains not multicast group
addresses but unicast addresses.

This table is fully separate from the default unicast table. However,
RPF lookup can include the unicast table.

.. clicmd:: ip mroute PREFIX NEXTHOP [DISTANCE]

   Adds a static route entry to the Multicast RIB. This performs exactly as the
   ``ip route`` command, except that it inserts the route in the Multicast RIB
   instead of the Unicast RIB.
   These routes are only used for RPF lookup and will not be used by zebra for
   insertion into the kernel *or* for normal rib processing. As such it is
   possible to create weird states with these commands. Use with caution. Most
   of the time this will not be necessary.

.. clicmd:: show [ip|ipv6] rpf

   Prints the entire Multicast RIB. Note that this is independent of the
   configured RPF lookup mode, the Multicast RIB may be printed yet not
   used at all.

.. clicmd:: show [ip|ipv6] rpf ADDR

   Performs a Multicast RPF lookup using the Multicast RIB only.
   ADDR specifies the multicast source address to look up. Note that this is
   independent of the configured RPF lookup mode.

   ::

      > show ip rpf 192.0.2.1
      Routing entry for 192.0.2.0/24 using Multicast RIB
      Known via "kernel", distance 0, metric 0, best
      * 198.51.100.1, via eth0


   Indicates that a multicast source lookup for 192.0.2.1 against the
   Multicast RIB would use an entry for 192.0.2.0/24 with a gateway of
   198.51.100.1.

.. clicmd:: show ip pim [vrf NAME] nexthop-lookup ADDR [GROUP]

   Performs a nexthop lookup according to the configured RPF lookup mode.
   This performs the lookup for a given source address, and optionally with
   a group address, which may effect the nexthop decision.

   ::

      > show ip pim nexthop-lookup 192.0.2.1
      (192.0.2.1, *) --- Nexthop 198.10.10.1 Interface eth1


   Indicates the a source lookup for 192.0.2.1 according to the configured RPF
   lookup mode would use the gateway address 192.10.10.1 on interface eth1.


.. _pim-interface-configuration:

PIM Interface Configuration
===========================

PIM interface commands allow you to configure an interface as either a Receiver
or a interface that you would like to form pim neighbors on. If the interface
is in a vrf, enter the interface command with the vrf keyword at the end.

.. clicmd:: ip pim active-active

   Turn on pim active-active configuration for a Vxlan interface.  This
   command will not do anything if you do not have the underlying ability
   of a mlag implementation.

.. clicmd:: ip pim bsm

   Tell pim that we would like to use this interface to process bootstrap
   messages. This is enabled by default. 'no' form of this command is used to
   restrict bsm messages on this interface.

.. clicmd:: ip pim unicast-bsm

   Tell pim that we would like to allow interface to process unicast bootstrap
   messages. This is enabled by default. 'no' form of this command is used to
   restrict processing of unicast bsm messages on this interface.

.. clicmd:: ip pim drpriority (0-4294967295)

   Set the DR Priority for the interface. This command is useful to allow the
   user to influence what node becomes the DR for a lan segment.

.. clicmd:: ip pim hello (1-65535) (1-65535)

   Set the pim hello and hold interval for a interface.

.. clicmd:: ip pim [sm | dm | sm-dm]

   Enable pim on this interface. pim will use this interface to form pim neighbors,
   and start exchaning pim protocol messages with those neighbors. The optional argument
   determines what mode pim will use this interface for. ``sm`` enables sparse mode,
   ``dm`` enables dense mode, while ``sm-dm`` enables sparse-dense mode.

   Please note that this command does not enable the reception of IGMP
   reports on the interface. Refer to the next `ip igmp` command for IGMP
   management.

.. clicmd:: ip pim ssm prefix-list PREFIX_LIST

   Configure the Source-Specific-Multicast group range. Defaults to 232.0.0.0/8.

.. clicmd:: ip pim dm prefix-list PREFIX_LIST

   Limit dense mode multicast to the range configured with prefix-list. By default
   there is no limit.

.. clicmd:: ip pim allowed-neighbors prefix-list PREFIX_LIST

   Only establish sessions with PIM neighbors allowed by the prefix-list.

.. clicmd:: ip pim use-source A.B.C.D

   If you have multiple addresses configured on a particular interface
   and would like pim to use a specific source address associated with
   that interface.

.. clicmd:: ip pim passive

   Disable sending and receiving pim control packets on the interface.

.. clicmd:: ip igmp

   Tell pim to receive IGMP reports and Query on this interface. The default
   version is v3. This command is useful on a LHR.

.. clicmd:: ip igmp require-router-alert

   Only accept IGMP reports with the router-alert IP option.

.. clicmd:: ip igmp join-group A.B.C.D [A.B.C.D]

   Join multicast group or source-group on an interface. This will result in
   an IGMP join happening through a local socket so that IGMP reports will be
   sent on this interface. It may also have the side effect of the kernel
   forwarding multicast traffic to the socket unnessarily.

.. clicmd:: ip igmp static-group A.B.C.D [A.B.C.D]

   Add a static multicast group or source-group on an interface. This will behave
   as if there is a receiver on this interface without any IGMP reports.

.. clicmd:: ip igmp proxy

   Tell pim to send proxy IGMP reports for joins occuring on all other
   interfaces on this interface. Join-groups on other interfaces will
   also be proxied. The default version is v3.

.. clicmd:: ip igmp immediate-leave

   Immediately leaves an IGMP group when receiving a IGMPv2 Leave packet.

.. clicmd:: ip igmp query-interval (1-65535)

   Set the IGMP query interval that PIM will use.

.. clicmd:: ip igmp query-max-response-time (1-65535)

   Set the IGMP query response timeout value. If an report is not returned in
   the specified time we will assume the S,G or \*,G has timed out.

.. clicmd:: ip igmp version (2-3)

   Set the IGMP version used on this interface. The default value is 3.

.. clicmd:: ip igmp max-groups (0-4294967295)

   Set the maximum number of IGMP groups that the can be joined on an interface.

.. clicmd:: ip igmp max-sources (0-4294967295)

   Set the maximum number of IGMP sources to learn per group.

.. clicmd:: ip multicast boundary oil WORD

   Set a PIM multicast boundary, based upon the WORD prefix-list. If a PIM join
   or IGMP report is received on this interface and the group is denied by the
   prefix-list, PIM will ignore the join or report.

   .. code-block:: frr

      prefix-list multicast-acl seq 5 permit 232.1.1.1/32
      prefix-list multicast-acl seq 10 deny 232.1.1.0/24
      prefix-list multicast-acl seq 15 permit any
      !
      interface r1-eth0
       ip pim
       ip igmp
       ip multicast boundary oil multicast-acl
      exit

.. clicmd:: ip multicast boundary ACCESS-LIST

   Set a PIM multicast boundary, based upon the ACCESS-LIST. If a PIM join
   or IGMP report is received on this interface and the (S,G) tuple is denied by the
   access-list, PIM will ignore the join or report.

   To filter on both source and group, the extended access-list syntax must be used.

   If both a prefix-list and access-list are configured for multicast boundaries,
   the prefix-list will be evaluated first (and must have a terminating "permit any"
   in order to also evaluate against the access-list).

   .. code-block:: frr

      access-list multicast-acl seq 5 permit ip host 10.0.20.2 host 232.1.1.1
      access-list multicast-acl seq 10 deny ip 10.0.20.0 0.0.0.255 232.1.1.0 0.0.0.255
      access-list multicast-acl seq 15 permit ip any any
      !
      interface r1-eth0
       ip pim
       ip igmp
       ip multicast boundary pim-acl
      exit

.. clicmd:: ip igmp last-member-query-count (1-255)

   Set the IGMP last member query count. The default value is 2. 'no' form of
   this command is used to to configure back to the default value.

.. clicmd:: ip igmp last-member-query-interval (1-65535)

   Set the IGMP last member query interval in deciseconds. The default value is
   10 deciseconds. 'no' form of this command is used to to configure back to the
   default value.

.. clicmd:: ip mroute INTERFACE A.B.C.D [A.B.C.D]

   Set a static multicast route for a traffic coming on the current interface to
   be forwarded on the given interface if the traffic matches the group address
   and optionally the source address.

.. clicmd:: ip igmp route-map ROUTE-MAP

   Apply the indicated route map to filter incoming IGMP joins.

   The following match statements can be used:

   * match ip multicast-group A.B.C.D

   * match ip multicast-group prefix-list IPV4-PREFIX-LIST

   * match ip multicast-source A.B.C.D

   * match ip multicast-source prefix-list IPV4-PREFIX-LIST

   * match multicast-interface INTERFACE-NAME

.. seealso::

   :ref:`bfd-pim-peer-config`

.. _msdp-configuration:

Multicast Source Discovery Protocol (MSDP) Configuration
========================================================

MSDP can be setup in different ways:

* MSDP meshed-group: where all peers are connected with each other creating
  a fully meshed network. SAs (source active) messages are not forwarded in
  this mode because the origin is able to send SAs to all members.

  This setup is commonly used with anycast.

* MSDP peering: when there is one or more peers that are not fully meshed. SAs
  may be forwarded depending on the result of filtering and RPF checks.

  This setup is commonly consistent with BGP peerings (for RPF checks).

* MSDP default peer: there is only one peer and all SAs will be forwarded
  there.

.. note::

   MSDP default peer is not implemented.

Commands available for MSDP
---------------------------

.. note::

   MSDP configuration is available under 'router pim'.

.. clicmd:: msdp timers (1-65535) (1-65535) [(1-65535)]

   Configure global MSDP timers.

   First value is the keep-alive interval. This configures the interval in
   seconds between keep-alive messages. The default value is 60 seconds. It
   should be less than the remote hold time.

   Second value is the hold-time. This configures the interval in seconds before
   closing a non responding connection. The default value is 75. This value
   should be greater than the remote keep alive time.

   Third value is the connection retry interval and it is optional. This
   configures the interval between connection attempts. The default value
   is 30 seconds.

.. clicmd:: msdp mesh-group WORD member A.B.C.D

   Create or update a mesh group to include the specified MSDP peer.

.. clicmd:: msdp mesh-group WORD source A.B.C.D

   Create or update a mesh group to set the source address used to connect to
   peers.

.. clicmd:: msdp peer A.B.C.D source A.B.C.D [as AS_NUMBER]

   Create a regular MSDP session with peer using the specified source address.

   Optionally the Autonomous Number (AS) can be provided for eBGP assisted
   loop detection (see RFC 4611 Section 2.1. Peering between PIM Border
   Routers).

   .. note::

      The BGP configuration must be enabled in order for this feature to work:

      ::

         bgp send-extra-data zebra

      This knob causes BGP to send the AS Path information to ``zebra`` so
      MSDP can use that information.

.. clicmd:: msdp peer A.B.C.D sa-filter ACL_NAME <in|out>

   Configure incoming or outgoing SA filtering rule.

   .. note::

      The filtering will only take effect starting from the command
      application.

.. clicmd:: msdp peer A.B.C.D sa-limit <AMOUNT>

   Configure the maximum number of SAs to learn from peer.

.. clicmd:: msdp peer A.B.C.D password WORD

   Use MD5 authentication to connect with the remote peer.

   .. note::

      The authentication will only take effect when starting a new
      connection.

      To apply it immediately call `clear ip msdp peer A.B.C.D`.

.. clicmd:: msdp originator-id A.B.C.D

   Use the specified originator ID instead of the multicast RP group.

.. clicmd:: msdp shutdown

   Shutdown the MSDP sessions in this PIM instance.


.. _show-pim-information:

Show PIM Information
====================

All PIM show commands are vrf aware and typically allow you to insert a
specified vrf command if information is desired about a specific vrf. If no
vrf is specified then the default vrf is assumed. Finally the special keyword
'all' allows you to look at all vrfs for the command. Naming a vrf 'all' will
cause great confusion.

.. clicmd:: show ip igmp interface

   Display IGMP interface information.

.. clicmd:: show ip igmp [vrf NAME] join [json]

   Display IGMP static join information.

.. clicmd:: show ip igmp [vrf NAME] groups [INTERFACE [GROUP]] [detail] [json]

   Display IGMP groups information.

.. clicmd:: show ip igmp groups retransmissions

   Display IGMP group retransmission information.

.. clicmd:: show ip igmp [vrf NAME] proxy [json]

   Display IGMP proxy join information.

.. clicmd:: show ip igmp [vrf NAME] sources [json]

   Display IGMP sources information.

.. clicmd:: show ip igmp sources retransmissions

   Display IGMP source retransmission information.

.. clicmd:: show ip igmp statistics

   Display IGMP statistics information.

.. clicmd:: show ip multicast

   Display various information about the interfaces used in this pim instance.

.. clicmd:: show ip mroute [vrf NAME] [A.B.C.D [A.B.C.D]] [fill] [json]

   Display information about installed into the kernel S,G mroutes.  If
   one address is specified we assume it is the Group we are interested
   in displaying data on.  If the second address is specified then it is
   Source Group.  The keyword `fill` says to fill in all assumed data
   for test/data gathering purposes.

.. clicmd:: show ip mroute [vrf NAME] count [json]

   Display information about installed into the kernel S,G mroutes and in
   addition display data about packet flow for the mroutes for a specific
   vrf.

.. clicmd:: show ip mroute vrf all count [json]

   Display information about installed into the kernel S,G mroutes and in
   addition display data about packet flow for the mroutes for all vrfs.

.. clicmd:: show ip mroute [vrf NAME] summary [json]

   Display total number of S,G mroutes and number of S,G mroutes installed
   into the kernel for a specific vrf.

.. clicmd:: show ip mroute vrf all summary [json]

   Display total number of S,G mroutes and number of S,G mroutes
   installed into the kernel for all vrfs.

.. clicmd:: show ip msdp mesh-group

   Display the configured mesh-groups, the local address associated with each
   mesh-group, the peer members included in each mesh-group, and their status.

.. clicmd:: show ip msdp peer

   Display information about the MSDP peers. That includes the peer address,
   the local address used to establish the connection to the peer, the
   connection status, and the number of active sources.

.. clicmd:: show ip pim assert

   Display information about asserts in the PIM system for S,G mroutes.
   This command does not show S,G Channel states that in a NOINFO state.

.. clicmd:: show ip pim assert-internal

   Display internal assert state for S,G mroutes

.. clicmd:: show ip pim assert-metric

   Display metric information about assert state for S,G mroutes

.. clicmd:: show ip pim assert-winner-metric

   Display winner metric for assert state for S,G mroutes

.. clicmd:: show ip pim group-type

   Display SSM group ranges.

.. clicmd:: show ip pim interface

   Display information about interfaces PIM is using.

.. clicmd:: show ip pim mlag [vrf NAME|all] interface [detail|WORD] [json]

   Display mlag interface information.

.. clicmd:: show ip pim join

   Display information about PIM joins received.  If one address is specified
   then we assume it is the Group we are interested in displaying data on.
   If the second address is specified then it is Source Group.

.. clicmd:: show ip pim local-membership

   Display information about PIM interface local-membership.

.. clicmd:: show ip pim mlag summary [json]

   Display mlag information state that PIM is keeping track of.

.. clicmd:: show ip pim neighbor

   Display information about PIM neighbors.

.. clicmd:: show ip pim nexthop

   Display information about pim nexthops that are being used.

.. clicmd:: show ip pim nexthop-lookup

   Display information about a S,G pair and how the RPF would be chosen. This
   is especially useful if there are ECMP's available from the RPF lookup.

.. clicmd:: show ip pim [vrf NAME] rp-info [A.B.C.D/M] [json]

   Display information about RP's that are configured on this router.

   You can filter the output by specifying an arbitrary group range.

   .. code-block:: frr

      # show ip pim rp-info
      RP address       group/prefix-list   OIF               I am RP    Source   Group-Type
      192.168.10.123   225.0.0.0/24        eth2              yes        Static   ASM
      192.168.10.123   239.0.0.0/8         eth2              yes        Static   ASM
      192.168.10.123   239.4.0.0/24        eth2              yes        Static   SSM

      # show ip pim rp-info 239.4.0.0/25
      RP address       group/prefix-list   OIF               I am RP    Source   Group-Type
      192.168.10.123   239.0.0.0/8         eth2              yes        Static   ASM
      192.168.10.123   239.4.0.0/24        eth2              yes        Static   SSM

.. clicmd:: show ip pim [vrf NAME] autorp [json]

   Display information about AutoRP. Including state of AutoRP Discovery parsing
   and configured AutoRP candidate RP information.

.. clicmd:: show ip pim rpf

   Display information about currently being used S,G's and their RPF lookup
   information. Additionally display some statistics about what has been
   happening on the router.

.. clicmd:: show ip pim secondary

   Display information about an interface and all the secondary addresses
   associated with it.

.. clicmd:: show ip pim state

   Display information about known S,G's and incoming interface as well as the
   OIL and how they were chosen.

.. clicmd:: show ip pim [vrf NAME] upstream [A.B.C.D [A.B.C.D]] [json]

   Display upstream information about a S,G mroute.  Allow the user to
   specify sub Source and Groups that we are only interested in.

.. clicmd:: show ip pim upstream-join-desired

   Display upstream information for S,G's and if we desire to
   join the multicast tree

.. clicmd:: show ip pim upstream-rpf

   Display upstream information for S,G's and the RPF data associated with them.

.. clicmd:: show ip pim [vrf NAME] mlag upstream [A.B.C.D [A.B.C.D]] [json]

   Display upstream entries that are synced across MLAG switches.
   Allow the user to specify sub Source and Groups address filters.

.. clicmd:: show ip pim mlag summary

   Display PIM MLAG (multi-chassis link aggregation) session status and
   control message statistics.

.. clicmd:: show ip pim bsr [vrf NAME] [json]

   Display current bsr, its uptime and last received bsm age.

.. clicmd:: show ip pim bsr candidate-bsr [vrf NAME] [json]

   Display information about the candidate BSR state on this router.

.. clicmd:: show ip pim bsr candidate-rp [vrf NAME] [json]

   Display information about the candidate RP state on this router.

.. clicmd:: show ip pim bsr candidate-rp-database [vrf NAME] [json]

   Display the current list of candidate RPs received by this router.

.. clicmd:: show ip pim bsr groups [vrf NAME] [json]

   Display the current list of multicast group mapping received by
   this router from candidate RPs.

.. clicmd:: show ip pim bsr rp-info [vrf NAME] [json]

   Display group-to-rp mappings received from E-BSR.

.. clicmd:: show ip pim bsm-database [vrf NAME] [json]

   Display all fragments of stored bootstrap message in user readable format.

.. clicmd:: mtrace A.B.C.D [A.B.C.D]

   Display multicast traceroute towards source, optionally for particular group.

.. clicmd:: show ip multicast count [vrf NAME] [json]

   Display multicast data packets count per interface for a vrf.

.. clicmd:: show ip multicast count vrf all [json]

   Display multicast data packets count per interface for all vrf.


.. seealso::

   :ref:`pim-multicast-rib`


PIM Debug Commands
==================

The debugging subsystem for PIM behaves in accordance with how FRR handles
debugging. You can specify debugging at the enable CLI mode as well as the
configure CLI mode. If you specify debug commands in the configuration cli
mode, the debug commands can be persistent across restarts of the FRR pimd if
the config was written out.

.. clicmd:: debug igmp

   This turns on debugging for IGMP protocol activity.

.. clicmd:: debug mtrace

   This turns on debugging for mtrace protocol activity.

.. clicmd:: debug mroute

   This turns on debugging for PIM interaction with kernel MFC cache.

.. clicmd:: debug pim events

   This turns on debugging for PIM system events. Especially timers.

.. clicmd:: debug pim nht

   This turns on debugging for PIM nexthop tracking. It will display
   information about RPF lookups and information about when a nexthop changes.

.. clicmd:: debug pim nht detail

   This turns on debugging for PIM nexthop in detail. This is not enabled
   by default.

.. clicmd:: debug pim graft

   This turns on debugging for PIM graft message processing. Graft messages are similar to PIM joins
   but are specifically used for PIM dense mode. This is not enabled by default.

.. clicmd:: debug pim state-refresh

   This turns on debugging for PIM state-refresh message processing. State-refresh messages are used
   in PIM dense mode. This is not enabled by default.

.. clicmd:: debug pim packet-dump

   This turns on an extraordinary amount of data. Each pim packet sent and
   received is dumped for debugging purposes. This should be considered a
   developer only command.

.. clicmd:: debug pim packets

   This turns on information about packet generation for sending and about
   packet handling from a received packet.

.. clicmd:: debug pim trace

   This traces pim code and how it is running.

.. clicmd:: debug pim bsm

   This turns on debugging for BSR message processing.

.. clicmd:: debug pim zebra

   This gathers data about events from zebra that come up through the ZAPI.

.. clicmd:: debug pim autorp

   This turns on debugging for PIM AutoRP protocol events.

PIM Clear Commands
==================
Clear commands reset various variables.

.. clicmd:: clear ip interfaces

   Reset interfaces.

.. clicmd:: clear ip igmp interfaces

   Reset IGMP interfaces.

.. clicmd:: clear ip mroute

   Reset multicast routes.

.. clicmd:: clear ip mroute [vrf NAME] count

   When this command is issued, reset the counts of data shown for
   packet count, byte count and wrong interface to 0 and start count
   up from this spot.

.. clicmd:: clear ip pim interfaces

   Reset PIM interfaces.

.. clicmd:: clear ip pim oil

   Rescan PIM OIL (output interface list).

.. clicmd:: clear ip pim [vrf NAME] bsr-data

   This command will clear the BSM scope data struct. This command also
   removes the next hop tracking for the bsr and resets the upstreams
   for the dynamically learnt RPs.

.. clicmd:: clear ip msdp peer A.B.C.D

   Reset MSDP peer connection.

   Use this command to set/unset MD5 authentication.

.. clicmd:: clear ip msdp [vrf all|vrf VRF_NAME] peer [A.B.C.D] counters

   Reset the MSDP peer(s) statistic counters.


PIM EVPN configuration
======================
To use PIM in the underlay for overlay BUM forwarding associate a multicast
group with the L2 VNI. The actual configuration is based on your distribution.
Here is an ifupdown2 example::

   auto vx-10100
   iface vx-10100
       vxlan-id 10100
       bridge-access 100
       vxlan-local-tunnelip 27.0.0.11
       vxlan-mcastgrp 239.1.1.100

.. note::

   PIM will see the ``vxlan-mcastgrp`` configuration and auto configure state
   to properly forward BUM traffic.

PIM also needs to be configured in the underlay to allow the BUM MDT to be
setup. This is existing PIM configuration:

- Enable pim on the underlay L3 interface via the "ip pim" command.
- Configure RPs for the BUM multicast group range.
- Ensure the PIM is enabled on the lo of the VTEPs and the RP.


Sample configuration
====================

.. code-block:: frr

   debug igmp
   debug pim
   debug pim zebra

   ! You may want to enable ssmpingd for troubleshooting
   ! See http://www.venaas.no/multicast/ssmping/
   !
   router pim
    ssmpingd 1.1.1.1
    ssmpingd 2.2.2.2

   ! HINTS:
   !  - Enable "ip pim ssm" on the interface directly attached to the
   !    multicast source host (if this is the first-hop router)
   !  - Enable "ip pim ssm" on pim-routers-facing interfaces
   !  - Enable "ip igmp" on IGMPv3-hosts-facing interfaces
   !  - In order to inject IGMPv3 local membership information in the
   !    PIM protocol state, enable both "ip pim ssm" and "ip igmp" on
   !    the same interface; otherwise PIM won't advertise
   !    IGMPv3-learned membership to other PIM routers

   interface eth0
    ip pim ssm
    ip igmp
