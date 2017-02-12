# GTP-U tunnel support: OvS kernel module extension
Implementation of GTP-U (GPRS Tunneling Protocol - User Plane) in the Open vSwitch 2.5.0 kernel module only. The whole repository contains only the source code files (new ".h" files and properly changed ".c" and ".h" files) which need to be overwritten in the OvS 2.5.0 root. The OvS 2.5.0 source code files can be downloaded from http://openvswitch.org/download/.

This tunnel implementation was object of my Master's degree thesis, it provides a native support (i.e. not via a tunnel OvS logical port, but extending directly the flow key data structure 'struct sw_flow_key' definition with GTP tunnel parameters, as the VLAN support is implemented) for matching GTP-U traffic, and tunnel encapsulation/decapsulation as new actions. Because the implementation adds support to the kernel module only, the only command line utility that can be used to add GTP-U flows is 'ovs-dpctl' via a new subcommand, 'add-gtpu-flow'. For example:

	# ovs-dpctl add-gtpu-flow "ipv4(dst=8.8.8.8,frag=no)" "push_gtp(src=192.168.1.1,dst=8.8.8.8,
                                                                  teid=1234), 1"
	Adds a new GTP-U flow, matching IPv4 packets destined to 8.8.8.8, encapsulating them inside a GTP-U tunnel with <192.168.1.1, 8.8.8.8> as its endpoint IPv4 addresses, and '1234' as its corresponding   tunnel label (TEID), and finally forwarding the just GTP-encapsulated packet over the OvS vport '1'.

	# ovs-dpctl add-gtpu-flow "gtp(teid=1234,dst=192.168.1.1)" "pop_gtp, 2"
	Adds a new GTP-U flow, matching GTP-U packets with 192.168.1.1 as tunnel's destination endpoint, and '1234' as tunnel's label ID, decapsulating the embedded user data packets, and finally forwarding them over the OvS vport '2'.

For more implementation details check `Thesis.pdf`.
