package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// DeviceManager handles listing, prompting, and selecting the most active network device.
type DeviceManager struct {
	Verbose bool
}

// ListDevicesWithPacketCounts lists all available network devices and their packet counts.
func (dm *DeviceManager) ListDevicesWithPacketCounts(duration time.Duration) ([]pcap.Interface, map[string]int, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, nil, err
	}

	if len(devices) == 0 {
		return nil, nil, fmt.Errorf("no devices found")
	}

	var wg sync.WaitGroup
	packetCounts := make(map[string]int)
	var mutex sync.Mutex

	for _, device := range devices {
		wg.Add(1)
		go func(deviceName string) {
			defer wg.Done()
			handle, err := pcap.OpenLive(deviceName, 1600, true, duration)
			if err != nil {
				return
			}
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			timeout := time.After(duration)

			count := 0
		loop:
			for {
				select {
				case <-timeout:
					break loop
				case _, ok := <-packetSource.Packets():
					if !ok {
						break loop
					}
					count++
				}
			}

			mutex.Lock()
			packetCounts[deviceName] = count
			mutex.Unlock()
		}(device.Name)
	}

	wg.Wait()

	// Display the summary of packet counts with detailed device information
	fmt.Println("Devices found (packet counts after 1.5 seconds):")
	for i, device := range devices {
		packetCount := packetCounts[device.Name]
		fmt.Printf("%d: %s (%d packets)\n", i+1, device.Name, packetCount)
		displayInterfaceDetails(device)
	}

	return devices, packetCounts, nil
}

// displayInterfaceDetails formats and displays the details of the network interface
func displayInterfaceDetails(device pcap.Interface) {
	for _, address := range device.Addresses {
		ip := address.IP.String()
		netmask := net.IP(address.Netmask).String()
		broadcast := "<none>"
		if address.Broadaddr != nil {
			broadcast = address.Broadaddr.String()
		}

		// Display IP address and netmask (if applicable)
		if isIPv4(ip) {
			fmt.Printf("    inet %s/%s brd %s\n", ip, netmaskToCIDR(netmask), broadcast)
		} else if isIPv6(ip) {
			fmt.Printf("    inet6 %s/%s scope %s\n", ip, netmaskToCIDR(netmask), "link")
		}

		// Display MAC address if available
		mac := getMACAddress(device.Name)
		if mac != "" {
			fmt.Printf("    link/ether %s\n", mac)
		} else {
			fmt.Printf("    link/ether <none>\n")
		}
		fmt.Printf("    State: UP\n") // Simplified state display
	}
}

// netmaskToCIDR converts a netmask to CIDR notation
func netmaskToCIDR(netmask string) string {
	if netmask == "<nil>" {
		return "unknown"
	}
	cidr, _ := net.IPMask(net.ParseIP(netmask).To4()).Size()
	return fmt.Sprintf("%d", cidr)
}

// getMACAddress retrieves the MAC address of the specified network interface
func getMACAddress(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	return iface.HardwareAddr.String()
}

// isIPv4 checks if an IP address is IPv4
func isIPv4(ip string) bool {
	return strings.Count(ip, ":") < 2
}

// isIPv6 checks if an IP address is IPv6
func isIPv6(ip string) bool {
	return strings.Count(ip, ":") >= 2
}
