package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"hash/fnv"
	"log"
	"net"
	"time"
)

const (
	exportBufferSize   = 1472
	netflow5HeaderSize = 24
	netflow5RecordSize = 48
)

type FlowKey struct {
	sourceIPAddress          net.IP
	destinationIPAddress     net.IP
	sourceTransportPort      uint16
	destinationTransportPort uint16
	protocolIdentifier       uint8
	ipClassOfService         uint8
}

type Flow struct {
	key              FlowKey
	tcpControlBits   uint16
	octetDeltaCount  uint64
	packetDeltaCount uint64
	start            time.Time
	end              time.Time
}

func (fk *FlowKey) Serialize() []byte {
	buf := make([]byte, 38)
	copy(buf[0:], fk.sourceIPAddress)
	copy(buf[16:], fk.destinationIPAddress)
	binary.BigEndian.PutUint16(buf[32:], fk.sourceTransportPort)
	binary.BigEndian.PutUint16(buf[34:], fk.destinationTransportPort)
	buf[36] = fk.protocolIdentifier
	buf[37] = fk.ipClassOfService
	return buf
}

func (fk *FlowKey) String() string {
	return fmt.Sprintf("sIP:%s, dIP:%s, sPort:%d, dPort:%d, Proto:%d, TOS:%d",
		fk.sourceIPAddress.String(), fk.destinationIPAddress.String(),
		fk.sourceTransportPort, fk.destinationTransportPort, fk.protocolIdentifier,
		fk.ipClassOfService)
}

func (f *Flow) SerializeNetflow5(baseTime time.Time) []byte {
	buf := make([]byte, netflow5RecordSize) //NetFlow version5 record
	copy(buf[0:], f.key.sourceIPAddress.To4())
	copy(buf[4:], f.key.destinationIPAddress.To4())
	binary.BigEndian.PutUint32(buf[8:], uint32(0))  // Nexthop Address, cannot lookup always 0
	binary.BigEndian.PutUint16(buf[10:], uint16(0)) // Input IFIndex, cannot lookup always 0
	binary.BigEndian.PutUint16(buf[12:], uint16(0)) // Output IFIndex, cannot lookup always 0
	binary.BigEndian.PutUint32(buf[16:], uint32(f.packetDeltaCount))
	binary.BigEndian.PutUint32(buf[20:], uint32(f.octetDeltaCount))
	binary.BigEndian.PutUint32(buf[24:], uint32(f.start.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
	binary.BigEndian.PutUint32(buf[28:], uint32(f.end.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
	binary.BigEndian.PutUint16(buf[32:], f.key.sourceTransportPort)
	binary.BigEndian.PutUint16(buf[34:], f.key.destinationTransportPort)
	buf[36] = uint8(0) //padding
	buf[37] = uint8(f.tcpControlBits)
	buf[38] = f.key.protocolIdentifier
	buf[39] = f.key.ipClassOfService
	binary.BigEndian.PutUint16(buf[40:], uint16(0)) // Source AS, cannot lookup always 0
	binary.BigEndian.PutUint16(buf[42:], uint16(0)) // Destination AS, cannot lookup always 0
	buf[44] = uint8(0)                              // Source Address Prefix Length
	buf[45] = uint8(0)                              // Destinatino Address Prefix Length
	binary.BigEndian.PutUint16(buf[46:], uint16(0)) // padding
	return buf
}

func (f *Flow) String() string {
	return fmt.Sprintf("%s, tcpFlag:%d, octets:%d, packet:%d, start:%s, end:%s",
		f.key.String(), f.tcpControlBits, f.octetDeltaCount, f.packetDeltaCount,
		f.start.String(), f.end.String())
}

func hashId(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

func tcpFlag(t *layers.TCP) uint16 {
	var f uint16
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	return f
}

var flowMap map[uint64]Flow
var flowChan chan Flow
var finished chan bool

func main() {
	pcapFile := flag.String("pcapfile", "", "Packet capture file to read")
	destination := flag.String("destination", "", "Destination for exporting")
	number := flag.Uint64("number", 0, "Maximum number of reading packets")
	flag.Parse()

	flowMap = make(map[uint64]Flow)
	flowChan = make(chan Flow)
	finished = make(chan bool)
	if *pcapFile != "" {
		if handle, err := pcap.OpenOffline(*pcapFile); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			count := uint64(0)
			for packet := range packetSource.Packets() {
				if count == 0 {
					go netflow5(*destination, packet.Metadata().CaptureInfo.Timestamp)
				}
				if (*number > 0) && (count > *number) {
					break
				}
				processPacket(packet)
				count++
			}
			for h, f := range flowMap {
				flowChan <- f
				delete(flowMap, h)
			}
			handle.Close() // finish pcap reading
		}
		close(flowChan)
	}
	_ = <-finished
}

func processPacket(packet gopacket.Packet) {
	var flow Flow

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		flow.key.sourceIPAddress = ip.SrcIP
		flow.key.destinationIPAddress = ip.DstIP
		flow.key.protocolIdentifier = uint8(ip.Protocol)
		flow.key.ipClassOfService = ip.TOS
	}
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		flow.key.sourceIPAddress = ip.SrcIP
		flow.key.destinationIPAddress = ip.DstIP
		flow.key.protocolIdentifier = uint8(ip.NextHeader)
		flow.key.ipClassOfService = ip.TrafficClass
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		flow.key.sourceTransportPort = uint16(tcp.SrcPort)
		flow.key.destinationTransportPort = uint16(tcp.DstPort)
		flow.tcpControlBits = tcpFlag(tcp)
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		flow.key.sourceTransportPort = uint16(udp.SrcPort)
		flow.key.destinationTransportPort = uint16(udp.DstPort)
	}
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		flow.key.destinationTransportPort = uint16(icmp.TypeCode)
	}
	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmp6Layer != nil {
		icmp, _ := icmp6Layer.(*layers.ICMPv6)
		flow.key.destinationTransportPort = uint16(icmp.TypeCode)
	}
	flowHash := hashId(flow.key.Serialize())
	f, ok := flowMap[flowHash]
	if ok { //flow exists in flowMap
		packetTimestamp := packet.Metadata().CaptureInfo.Timestamp
		inactiveDuration := packetTimestamp.Sub(f.end)
		if inactiveDuration.Seconds() > 15 {
			flowChan <- f
			f.packetDeltaCount = 0    // reset flow
			f.octetDeltaCount = 0     // reset flow
			f.start = packetTimestamp // reset flow
			f.tcpControlBits = 0      // reset flow
		}
		f.packetDeltaCount++
		f.octetDeltaCount += uint64(packet.Metadata().CaptureInfo.Length)
		f.end = packetTimestamp
		f.tcpControlBits |= flow.tcpControlBits
		activeDuration := f.end.Sub(f.start)
		if (f.tcpControlBits&0x0001 > 0) || (activeDuration.Minutes()*60 > 1800) {
			flowChan <- f
			delete(flowMap, flowHash)
		}
		flowMap[flowHash] = f // update
	} else { //flow doesn't exist in flowMap
		flow.packetDeltaCount = 1
		flow.octetDeltaCount = uint64(packet.Metadata().CaptureInfo.Length)
		flow.end = packet.Metadata().CaptureInfo.Timestamp
		flow.start = flow.end
		f.tcpControlBits |= flow.tcpControlBits
		flowMap[flowHash] = flow
	}
}

func netflow5(destination string, firstPacketTime time.Time) {
	conn, err := net.Dial("udp", destination)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, exportBufferSize)

	flowCount := uint16(0)
	totalFlowCount := uint32(0)
	flowPerPacket := uint16((exportBufferSize - netflow5HeaderSize) / netflow5RecordSize)

	binary.BigEndian.PutUint16(buf[0:], uint16(5))  // NetFlow v5 Header constant value
	buf[20] = uint8(0)                              // engine type
	buf[21] = uint8(0)                              // engine id
	binary.BigEndian.PutUint16(buf[22:], uint16(0)) // sample rate

	var flowEnd time.Time
	for {
		flow, ok := <-flowChan
		if ok {
			if flow.key.sourceIPAddress.To4() == nil {
				continue
			}
			copy(buf[netflow5HeaderSize+flowCount*netflow5RecordSize:],
				flow.SerializeNetflow5(firstPacketTime))
			flowCount++
			totalFlowCount++
			fmt.Printf("%d %s\n", totalFlowCount, flow.String())
			flowEnd = flow.end
		}
		if (flowCount == flowPerPacket) || !ok { // make netflow v5 header and export
			binary.BigEndian.PutUint16(buf[2:], flowCount)
			binary.BigEndian.PutUint32(buf[4:],
				uint32(flowEnd.Sub(firstPacketTime).Nanoseconds()/int64(time.Millisecond)))
			binary.BigEndian.PutUint32(buf[8:], uint32(flowEnd.Unix()))
			binary.BigEndian.PutUint32(buf[12:],
				uint32(flowEnd.UnixNano()-flowEnd.Unix()*int64(time.Nanosecond)))
			binary.BigEndian.PutUint32(buf[16:], totalFlowCount)
			conn.Write(buf[:netflow5HeaderSize+netflow5RecordSize*flowCount]) // UDP Send
			flowCount = 0
		}
		if !ok {
			break
		}
	}
	conn.Close()
	finished <- true
}
