# vhost-pci

This doc introduces the steps to try the vhost-pci
implementation.

1. Compilation configuration
    1.1 In addition to the configuration options that are required for virtio-net, the following
        options are required for vhost-pci-net in the guest kernel .config:
        "CONFIG_HOTPLUG_PCI_ACPI=y",
        "CONFIG_VHOST_PCI_NET=y"

2. Booting configuration
    2.1 Slave guest
        2.1.1 Kernel booting
            add
            "vhost_pci_net.napi_weight=0",
            to let the vhost-pci-net driver use polling to receive packets.
        2.1.2 QEMU booting
            add
            "-chardev socket,id=slave1,server,wait=off,path=/opt/vhost-pci-slave1 \
            -vhost-pci-slave socket,chardev=slave1",
            to create a vhost-pci-slave
    2.2 Master guest
        2.2.1 Kernel booting
            add
            "virtio_net.napi_weight=0",
            to let the virtio_net driver use polling to receive packets.
        2.2.2 QEMU booting
            1) "-m 512M -mem-prealloc -realtime mlock=on \
               "-object memory-backend-file,id=mem,size=512M,mem-path=/mnt/hugepages,share=on",
               make sure the master guest memory is less than 1GB. Current qemu doesn't
               support large hotplugged device memory.
            2) " -chardev socket,id=sock2,path=/opt/vhost-pci-slave1 \
		 -netdev type=vhost-user,id=net2,chardev=sock2,vhostforce \
		 -device virtio-net-pci,mac=52:54:00:00:00:02,netdev=net2",
                make sure that the socket path that associates with the virtio-net device is
               identical to the slave socket path.

3. After guest boots
    UP the net device, for example:
	1) in the slave guest: ifconfig eth0 192.168.2.11, where eth0 corresponds to
           the vhost-pci net device;
        2) in the master guest: ifconfig eth0 192.168.2.12, where eth1 corresponds to
           the virtio net device;

4. Test
    4.1 Test with Ping
        Example of Ping from the slave guest: Ping 192.168.2.12 -I eth0

    4.2 Test with Netperf
	Example of netperf from the slave guest: netperf -H 192.168.2.12 -t TCP_STREAM -l 10
