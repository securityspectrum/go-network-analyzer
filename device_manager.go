package main

import (
	"fmt"
	"log"
	"strconv"
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

	// Display the summary of packet counts
	fmt.Println("Devices found (packet counts after 1.5 seconds):")
	for i, device := range devices {
		packetCount := packetCounts[device.Name]
		fmt.Printf("%d: %s: %d packets\n", i, device.Name, packetCount)
	}

	return devices, packetCounts, nil
}

func (dm *DeviceManager) PromptUserOrAutoSelect(devices []pcap.Interface, packetCounts map[string]int, duration time.Duration) (string, error) {
	fmt.Println("\nPlease select a device number to capture packets from:")
	fmt.Println("If no selection is made within 5 seconds, the device with the highest packet count will be automatically selected.")

	userInput := make(chan string, 1)
	go func() {
		var deviceIndex string
		fmt.Scanln(&deviceIndex)
		userInput <- deviceIndex
	}()

	select {
	case input := <-userInput:
		index, err := strconv.Atoi(input)
		if err != nil || index < 0 || index >= len(devices) {
			return "", fmt.Errorf("invalid device number: %s", input)
		}
		log.Printf("Selected device: %s", devices[index].Name)
		return devices[index].Name, nil
	case <-time.After(duration):
		mostActiveDevice := findMostActiveDevice(packetCounts)
		fmt.Printf("\nNo input received. Automatically selected device: %s with %d packets\n", mostActiveDevice, packetCounts[mostActiveDevice])
		return mostActiveDevice, nil
	}
}

func findMostActiveDevice(packetCounts map[string]int) string {
	var mostActiveDevice string
	maxPackets := 0
	for device, count := range packetCounts {
		if count > maxPackets {
			maxPackets = count
			mostActiveDevice = device
		}
	}
	return mostActiveDevice
}
