package godnscapture

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mkdns "github.com/miekg/dns"
	"net"
	"os"
	"os/signal"
)

type CaptureOptions struct {
	DevName                       string
	Filter                        string
	Port                          uint16
	GcTime                        time.Duration
	ResultChannel                 chan<- DnsResult
	PacketHandlerCount            uint
	PacketChannelSize             uint
	TcpHandlerCount               uint
	TcpAssemblyChannelSize        uint
	TcpResultChannelSize          uint
	Ip4DefraggerChannelSize       uint
	Ip4DefraggerReturnChannelSize uint
	Done                          chan bool
}

type DnsCapturer struct {
	options    CaptureOptions
	processing chan gopacket.Packet
}

type DnsResult struct {
	Timestamp    time.Time
	Dns          mkdns.Msg
	IPVersion    uint8
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     string
	PacketLength uint16
}

func initialize(devName, filter string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, 10*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	// Set Filter
	fmt.Fprintf(os.Stderr, "Using Device: %s\n", devName)
	fmt.Fprintf(os.Stderr, "Filter: %s\n", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	return handle
}

func handleInterrupt(done chan bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Errorf("SIGINT")
			close(done)
			return
		}
	}()
}

func NewDnsCapturer(options CaptureOptions) DnsCapturer {
	var tcp_channel []chan tcpPacket

	tcp_return_channel := make(chan tcpData, options.TcpResultChannelSize)
	processing_channel := make(chan gopacket.Packet, options.PacketChannelSize)
	ip4DefraggerChannel := make(chan layers.IPv4, options.Ip4DefraggerChannelSize)
	ip4DefraggerReturn := make(chan layers.IPv4, options.Ip4DefraggerReturnChannelSize)

	for i := uint(0); i < options.TcpHandlerCount; i++ {
		tcp_channel = append(tcp_channel, make(chan tcpPacket, options.TcpAssemblyChannelSize))
		go tcpAssembler(tcp_channel[i], tcp_return_channel, options.GcTime, options.Done)
	}

	go ipv4Defragger(ip4DefraggerChannel, ip4DefraggerReturn, options.GcTime, options.Done)

	encoder := PacketEncoder{
		options.Port,
		processing_channel,
		ip4DefraggerChannel,
		ip4DefraggerReturn,
		tcp_channel,
		tcp_return_channel,
		options.ResultChannel,
		options.Done,
	}

	for i := uint(0); i < options.PacketHandlerCount; i++ {
		go encoder.run()
	}
	return DnsCapturer{options, processing_channel}
}

func (capturer *DnsCapturer) Start() {
	options := capturer.options
	handle := initialize(options.DevName, options.Filter)
	defer handle.Close()

	// Setup SIGINT handling
	handleInterrupt(options.Done)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true
	log.Println("Waiting for packets")
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				fmt.Println("PacketSource returned nil.")
				close(options.Done)
				return
			}
			select {
			case capturer.processing <- packet:
			default:
			}
		case <-options.Done:
			return
		}
	}
}
