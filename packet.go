package godnscapture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	mkdns "github.com/miekg/dns"
	"net"
)

type PacketEncoder struct {
	port              uint16
	input             <-chan gopacket.Packet
	ip4Defrgger       chan<- layers.IPv4
	ip4DefrggerReturn <-chan layers.IPv4
	tcpAssembly       []chan tcpPacket
	tcpReturnChannel  <-chan tcpData
	resultChannel     chan<- DnsResult
	done              chan bool
}

func ipv4Defragger(ipInput <-chan layers.IPv4, ipOut chan layers.IPv4, done chan bool) {
	ipv4Defragger := ip4defrag.NewIPv4Defragmenter()
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case ip := <-ipInput:
			result, err := ipv4Defragger.DefragIPv4(&ip)
			if err == nil && result != nil {
				ipOut <- *result
			}
		case <-ticker.C:
			ipv4Defragger.DiscardOlderThan(time.Now().Add(time.Minute * -1))
		case <-done:
			ticker.Stop()
			return
		}
	}
}

func (encoder *PacketEncoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, flow gopacket.Flow, IPVersion uint8, SrcIP, DstIP net.IP) {
	for _, layerType := range *foundLayerTypes {
		switch layerType {
		case layers.LayerTypeUDP:
			if uint16(udp.DstPort) == encoder.port || uint16(udp.SrcPort) == encoder.port {
				msg := mkdns.Msg{}
				if err := msg.Unpack(udp.Payload); err == nil {
					encoder.resultChannel <- DnsResult{time.Now(), msg, IPVersion, SrcIP, DstIP, "udp", uint16(len(udp.Payload))}
				}
			}
		case layers.LayerTypeTCP:
			if uint16(tcp.SrcPort) == encoder.port || uint16(tcp.DstPort) == encoder.port {
				encoder.tcpAssembly[flow.FastHash()%uint64(len(encoder.tcpAssembly))] <- tcpPacket{
					IPVersion,
					*tcp,
					time.Now(),
					flow,
				}
			}
		}
	}

}

func (encoder *PacketEncoder) run() {
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
				encoder.resultChannel <- DnsResult{time.Now(), msg, data.IPVersion, data.SrcIp, data.DstIp, "tcp", uint16(len(data.data))}
			}
		case ip4 = <-encoder.ip4DefrggerReturn:
			// Packet was defragged, parse the remaining data
			if ip4.Protocol == layers.IPProtocolUDP {
				parserOnlyUDP.DecodeLayers(ip4.Payload, &foundLayerTypes)
			} else if ip4.Protocol == layers.IPProtocolTCP {
				parserOnlyTCP.DecodeLayers(ip4.Payload, &foundLayerTypes)
			} else {
				// Protocol not supported
				break
			}
			encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip4.NetworkFlow(), 4, ip4.SrcIP, ip4.DstIP)
		case packet := <-encoder.input:
			{
				_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
				// first parse the ip layer, so we can find fragmented packets
				for _, layerType := range foundLayerTypes {
					switch layerType {
					case layers.LayerTypeIPv4:
						// Check for fragmentation
						if ip4.Flags&layers.IPv4DontFragment == 0 && (ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) {
							// Packet is fragmented, send it to the defragger
							encoder.ip4Defrgger <- ip4
							break
						}
						encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip4.NetworkFlow(), 4, ip4.SrcIP, ip4.DstIP)
						break
					case layers.LayerTypeIPv6:
						// Store the packet metadata
						encoder.processTransport(&foundLayerTypes, &udp, &tcp, ip6.NetworkFlow(), 4, ip6.SrcIP, ip6.DstIP)
					}
				}
				break
			}
		case <-encoder.done:
			break
		}
	}
}
