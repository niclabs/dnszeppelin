package godnscapture

import (
	"time"

	"github.com/fdns/godnscapture/ip6defrag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	mkdns "github.com/miekg/dns"
	"net"
)

type packetEncoder struct {
	port              uint16
	input             <-chan gopacket.Packet
	ip4Defrgger       chan<- ipv4ToDefrag
	ip6Defrgger       chan<- ipv6FragmentInfo
	ip4DefrggerReturn <-chan ipv4Defragged
	ip6DefrggerReturn <-chan ipv6Defragged
	tcpAssembly       []chan tcpPacket
	tcpReturnChannel  <-chan tcpData
	resultChannel     chan<- DNSResult
	done              chan bool
}

type ipv4ToDefrag struct {
	ip        layers.IPv4
	timestamp time.Time
}

type ipv4Defragged struct {
	ip        layers.IPv4
	timestamp time.Time
}

type ipv6FragmentInfo struct {
	ip         layers.IPv6
	ipFragment layers.IPv6Fragment
	timestamp  time.Time
}

type ipv6Defragged struct {
	ip        layers.IPv6
	timestamp time.Time
}

func ipv4Defragger(ipInput <-chan ipv4ToDefrag, ipOut chan ipv4Defragged, gcTime time.Duration, done chan bool) {
	ipv4Defragger := ip4defrag.NewIPv4Defragmenter()
	ticker := time.NewTicker(1 * gcTime)
	for {
		select {
		case packet := <-ipInput:
			result, err := ipv4Defragger.DefragIPv4(&packet.ip)
			if err == nil && result != nil {
				ipOut <- ipv4Defragged{
					*result,
					packet.timestamp,
				}
			}
		case <-ticker.C:
			ipv4Defragger.DiscardOlderThan(time.Now().Add(gcTime * -1))
		case <-done:
			ticker.Stop()
			return
		}
	}
}

func ipv6Defragger(ipInput <-chan ipv6FragmentInfo, ipOut chan ipv6Defragged, gcTime time.Duration, done chan bool) {
	ipv4Defragger := ip6defrag.NewIPv6Defragmenter()
	ticker := time.NewTicker(1 * gcTime)
	for {
		select {
		case packet := <-ipInput:
			result, err := ipv4Defragger.DefragIPv6(&packet.ip, &packet.ipFragment)
			if err == nil && result != nil {
				ipOut <- ipv6Defragged{
					*result,
					packet.timestamp,
				}
			}
		case <-ticker.C:
			ipv4Defragger.DiscardOlderThan(time.Now().Add(gcTime * -1))
		case <-done:
			ticker.Stop()
			return
		}
	}
}

func (encoder *packetEncoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, flow gopacket.Flow, timestamp time.Time, IPVersion uint8, SrcIP, DstIP net.IP) {
	for _, layerType := range *foundLayerTypes {
		switch layerType {
		case layers.LayerTypeUDP:
			if uint16(udp.DstPort) == encoder.port || uint16(udp.SrcPort) == encoder.port {
				msg := mkdns.Msg{}
				err := msg.Unpack(udp.Payload)
				// Process if no error or truncated, as it will have most of the information it have available
				if err == nil || err == mkdns.ErrTruncated {
					encoder.resultChannel <- DNSResult{timestamp, msg, IPVersion, SrcIP, DstIP, "udp", uint16(len(udp.Payload))}
				}
			}
		case layers.LayerTypeTCP:
			if uint16(tcp.SrcPort) == encoder.port || uint16(tcp.DstPort) == encoder.port {
				encoder.tcpAssembly[flow.FastHash()%uint64(len(encoder.tcpAssembly))] <- tcpPacket{
					IPVersion,
					*tcp,
					timestamp,
					flow,
				}
			}
		}
	}

}

func (encoder *packetEncoder) run() {
	var ethLayer layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var udp layers.UDP
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4,
		&ip6,
		&udp,
		&tcp,
	)
	parserOnlyUDP := gopacket.NewDecodingLayerParser(
		layers.LayerTypeUDP,
		&udp,
	)
	parserOnlyTCP := gopacket.NewDecodingLayerParser(
		layers.LayerTypeTCP,
		&tcp,
	)
	foundLayerTypes := []gopacket.LayerType{}
	for {
		select {
		case data := <-encoder.tcpReturnChannel:
			msg := mkdns.Msg{}
			if err := msg.Unpack(data.data); err == nil {
				encoder.resultChannel <- DNSResult{data.timestamp, msg, data.IPVersion, data.SrcIP, data.DstIP, "tcp", uint16(len(data.data))}
			}
		case packet := <-encoder.ip4DefrggerReturn:
			// Packet was defragged, parse the remaining data
			if packet.ip.Protocol == layers.IPProtocolUDP {
				parserOnlyUDP.DecodeLayers(packet.ip.Payload, &foundLayerTypes)
			} else if ip4.Protocol == layers.IPProtocolTCP {
				parserOnlyTCP.DecodeLayers(packet.ip.Payload, &foundLayerTypes)
			} else {
				// Protocol not supported
				break
			}
			encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip4.NetworkFlow(), packet.timestamp, 4, packet.ip.SrcIP, packet.ip.DstIP)
		case packet := <-encoder.ip6DefrggerReturn:
			// Packet was defragged, parse the remaining data
			if packet.ip.NextHeader == layers.IPProtocolUDP {
				parserOnlyUDP.DecodeLayers(packet.ip.Payload, &foundLayerTypes)
			} else if packet.ip.NextHeader == layers.IPProtocolTCP {
				parserOnlyTCP.DecodeLayers(packet.ip.Payload, &foundLayerTypes)
			} else {
				// Protocol not supported
				break
			}
			encoder.processTransport(&foundLayerTypes, &udp, &tcp, packet.ip.NetworkFlow(), packet.timestamp, 6, packet.ip.SrcIP, packet.ip.DstIP)
		case packet := <-encoder.input:
			{
				timestamp := packet.Metadata().Timestamp
				if timestamp.IsZero() {
					timestamp = time.Now()
				}
				_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
				// first parse the ip layer, so we can find fragmented packets
				for _, layerType := range foundLayerTypes {
					switch layerType {
					case layers.LayerTypeIPv4:
						// Check for fragmentation
						if ip4.Flags&layers.IPv4DontFragment == 0 && (ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) {
							// Packet is fragmented, send it to the defragger
							encoder.ip4Defrgger <- ipv4ToDefrag{
								ip4,
								timestamp,
							}
							break
						}
						encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip4.NetworkFlow(), timestamp, 4, ip4.SrcIP, ip4.DstIP)
						break
					case layers.LayerTypeIPv6:
						// Store the packet metadata
						if ip6.NextHeader == layers.IPProtocolIPv6Fragment {
							// TODO: Move the parsing to DecodingLayer when gopacket support it
							if frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); frag != nil {
								encoder.ip6Defrgger <- ipv6FragmentInfo{
									ip6,
									*frag,
									timestamp,
								}
							}
						} else {
							encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip6.NetworkFlow(), timestamp, 6, ip6.SrcIP, ip6.DstIP)
						}
					}
				}
				break
			}
		case <-encoder.done:
			break
		}
	}
}
