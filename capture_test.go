package godnscapture

import (
	"testing"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	mkdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"time"
)

/* Helpers */

func generateUDPPacket(payload []byte) gopacket.Packet {
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()

	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version: 4,
		Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{127, 0, 0, 1},
		DstIP: net.IP{8, 8, 8, 8},
	}

	udpLayer := &layers.UDP{
		SrcPort: 53,
		DstPort: 53,
	}

	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)
}

func packTCP(payload []byte, seq uint32, syn bool) gopacket.Packet {
	// Generate the packet
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()

	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version: 4,
		Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{127, 0, 0, 1},
		DstIP: net.IP{8, 8, 8, 8},
	}

	tcpLayer := &layers.TCP{
		Seq: seq,
		SYN: syn,
		SrcPort: layers.TCPPort(53),
		DstPort: layers.TCPPort(53),
	}

	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(payload),
	)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

}

func createCapturer() (chan DnsResult, DnsCapturer) {
	resultChannel := make(chan DnsResult, 10)
	done := make(chan bool)
	capturer := NewDnsCapturer(CaptureOptions{
		"lo",
		"(ip or ip6)",
		53,
		5*time.Second,
		resultChannel,
		1,
		10,
		1,
		1,
		10,
		10,
		10,
		done,
	})
	return resultChannel, capturer
}


/* Tests */
func TestCreateCapture(t *testing.T) {
	rChannel, capturer := createCapturer()
	close(capturer.options.Done)
	close(rChannel)
}

func TestCaptureDNSParse(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createCapturer()
	defer close(capturer.options.Done)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	capturer.processing <- generateUDPPacket(pack)
	result := <-rChannel
	assert.Equal(t, 1, len(result.Dns.Question), "DNS Question decoded incorrectly")
	assert.Equal(t, "example.com.", result.Dns.Question[0].Name, "DNS Question decoded incorrectly")
	assert.Equal(t, mkdns.TypeA, result.Dns.Question[0].Qtype, "DNS Question decoded incorrectly")
}

func TestCaptureIP(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	capturer.processing <- generateUDPPacket(pack)
	result := <-rChannel
	assert.Equal(t, net.IPv4(127,0,0,1)[12:], result.SrcIP, "DNS Source IP parsed incorrectly")
	assert.Equal(t, net.IPv4(8,8,8,8)[12:], result.DstIP, "DNS Dest IP parsed incorrectly")
}

func TestCaptureTCP(t *testing.T) {
	t.Parallel()

	// Generate the data
	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	payload, _ := data.Pack()

	buf := []byte{0,0}
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	buf = append(buf, payload...)
	packet := packTCP(buf, 1, true)

	// Send the packet
	rChannel, capturer := createCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)
	capturer.processing <- packet
	result := <-rChannel
	assert.Equal(t, 1, len(result.Dns.Question), "TCP Question decoded incorrectly")
}

func TestCaptureTCPDivided(t *testing.T) {

	// Generate the data
	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	payload, _ := data.Pack()

	buf := []byte{0,0}
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	buf = append(buf, payload...)

	a := buf[:len(buf)/2]
	b := buf[len(buf)/2:]
	packetA := packTCP(a, 10, true)
	packetB := packTCP(b, 10+uint32(len(a))+1, false)
	assert.Equal(t, len(buf), len(a)+len(b), "Err")
	//return

	// Send the packet
	rChannel, capturer := createCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)
	capturer.processing <- packetB
	capturer.processing <- packetA
	result := <-rChannel
	assert.Equal(t, 1, len(result.Dns.Question), "TCP Question decoded incorrectly")
}
