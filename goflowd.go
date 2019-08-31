package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	//"github.com/pkg/profile"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const ( // goflowd parameters
	defaultFlowNumber        = 65536
	defaultSnapLength        = 1518
	exportBufferSize         = 1472
	netflow5HeaderSize       = 24
	netflow5RecordSize       = 48
	flowKeySize              = 38
	defaultFlowActiveTimeout = 1800
	defaultFlowIdleTimeout   = 15
)

const (
	tcpControlBitsFIN uint16 = 0x0001
	tcpControlBitsSYN uint16 = 0x0002
	tcpControlBitsRST uint16 = 0x0004
	tcpControlBitsPSH uint16 = 0x0008
	tcpControlBitsACK uint16 = 0x0010
	tcpControlBitsURG uint16 = 0x0020
	tcpControlBitsECE uint16 = 0x0040
	tcpControlBitsCWR uint16 = 0x0080
	tcpControlBitsNS  uint16 = 0x0100
)

const (
	flowEndReasonIdleTimeout     uint8 = 0x01
	flowEndReasonActiveTimeout   uint8 = 0x02
	flowEndReasonEndOfFlow       uint8 = 0x03
	flowEndReasonForceEnd        uint8 = 0x04
	flowEndReasonLackOfResources uint8 = 0x05
)

const (
	packetReaderOffline uint8 = 0x01
	packetReaderPromisc uint8 = 0x02
	packetReaderPcapgo  uint8 = 0x04
)

func fnv64a(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

type MeterStatistics struct {
	observedPacketTotalCount uint64 // goflowd original counter
	observedOctetTotalCount  uint64 // goflowd original counter
	observedFlowTotalCount   uint64
	ignoredPacketTotalCount  uint64
	ignoredOctetTotalCount   uint64
}
type ExporterStatistics struct {
	exportedMessageTotalCount    uint64
	exportedOctetTotalCount      uint64
	exportedFlowRecordTotalCount uint64
	notSentFlowTotalCount        uint64
	notSentPacketTotalCount      uint64
	notSentOctetTotalCount       uint64
}

type FlowKey struct {
	sourceIPAddress          net.IP
	destinationIPAddress     net.IP
	sourceTransportPort      uint16
	destinationTransportPort uint16
	protocolIdentifier       uint8
	ipClassOfService         uint8
}

type ParserParameters struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	udp     *layers.UDP
	icmp4   *layers.ICMPv4
	icmp6   *layers.ICMPv6
}

type Flow struct {
	key              FlowKey
	tcpControlBits   uint16
	octetDeltaCount  uint64
	packetDeltaCount uint64
	start            time.Time
	end              time.Time
}

func (flow *Flow) DecodeFromBytes(packetData []byte, ci gopacket.CaptureInfo, pp ParserParameters) error {
	flow.packetDeltaCount = 1
	flow.octetDeltaCount = uint64(ci.Length)
	flow.start, flow.end = ci.Timestamp, ci.Timestamp
	for _, typ := range pp.decoded {
		switch typ {
		//case layers.LayerTypeEthernet:
		case layers.LayerTypeIPv4:
			if pp.ip4.FragOffset > 0 {
				return fmt.Errorf("Fragment")
			}
			flow.key.sourceIPAddress = pp.ip4.SrcIP
			flow.key.destinationIPAddress = pp.ip4.DstIP
			flow.key.protocolIdentifier = uint8(pp.ip4.Protocol)
			flow.key.ipClassOfService = pp.ip4.TOS
		case layers.LayerTypeIPv6:
			flow.key.sourceIPAddress = pp.ip6.SrcIP
			flow.key.destinationIPAddress = pp.ip6.DstIP
			flow.key.protocolIdentifier = uint8(pp.ip6.NextHeader)
			flow.key.ipClassOfService = pp.ip6.TrafficClass
		case layers.LayerTypeTCP:
			flow.key.sourceTransportPort = uint16(pp.tcp.SrcPort)
			flow.key.destinationTransportPort = uint16(pp.tcp.DstPort)
			flow.tcpControlBits = tcpFlag(pp.tcp)
		case layers.LayerTypeUDP:
			flow.key.sourceTransportPort = uint16(pp.udp.SrcPort)
			flow.key.destinationTransportPort = uint16(pp.udp.DstPort)
		case layers.LayerTypeICMPv4:
			flow.key.sourceTransportPort = uint16(0)
			flow.key.destinationTransportPort = uint16(pp.icmp4.TypeCode)
		case layers.LayerTypeICMPv6:
			flow.key.sourceTransportPort = uint16(0)
			flow.key.destinationTransportPort = uint16(pp.icmp6.TypeCode)
		}
	}
	return nil
}

type FlowCacheParameters struct {
	maxFlows      uint64
	activeTimeout uint64
	idleTimeout   uint64
}
type FlowCache interface {
	Store(flow Flow, flowHashId uint64, flowChan chan Flow, fcp FlowCacheParameters) uint8
	ExpireAll(flowChan chan Flow, fcp FlowCacheParameters)
}
type FlowCacheSlice []Flow
type FlowCacheMap map[uint64]Flow

func NewFlowCache(storeMap bool, maxFlows uint64) FlowCache {
	if storeMap {
		return FlowCacheMap(make(map[uint64]Flow, maxFlows))
	}
	return FlowCacheSlice(make([]Flow, maxFlows))
}
func (flowCacheSlice FlowCacheSlice) Store(flow Flow, flowHashId uint64, flowChan chan Flow, fcp FlowCacheParameters) uint8 {
	flowEndReason := uint8(0)
	if flowCacheSlice[flowHashId].packetDeltaCount > 0 { //flow exists in flowCacheSlice
		flowEndReason = updateFlowCache(flow, &flowCacheSlice[flowHashId], flowChan, fcp)
	} else { //flow doesn't exist in flowCacheSlice
		flowCacheSlice[flowHashId] = flow
	}
	return flowEndReason
}
func (flowCacheSlice FlowCacheSlice) ExpireAll(flowChan chan Flow, fcp FlowCacheParameters) {
	for id := uint64(0); id < fcp.maxFlows; id++ {
		if flowCacheSlice[id].packetDeltaCount > 0 {
			flowChan <- flowCacheSlice[id]
		}
	}
}
func (flowCacheMap FlowCacheMap) Store(flow Flow, flowHashId uint64, flowChan chan Flow, fcp FlowCacheParameters) uint8 {
	flowEndReason := uint8(0)
	f, ok := flowCacheMap[flowHashId]
	if ok { //flow exists in flowCacheMap
		flowEndReason = updateFlowCache(flow, &f, flowChan, fcp)
		if flowEndReason == flowEndReasonEndOfFlow || flowEndReason == flowEndReasonActiveTimeout {
			delete(flowCacheMap, flowHashId)
		}
		flowCacheMap[flowHashId] = f // update
	} else { //flow doesn't exist in flowCacheMap
		flowCacheMap[flowHashId] = flow
	}
	return flowEndReason
}
func (flowCacheMap FlowCacheMap) ExpireAll(flowChan chan Flow, fcp FlowCacheParameters) {
	for id, f := range flowCacheMap {
		flowChan <- f
		delete(flowCacheMap, id)
	}
}

type PacketReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func NewPacketReader(packetReaderFlag uint8, pcapSource string, snaplen int32, file *os.File) (PacketReader, error) {
	if packetReaderFlag&packetReaderOffline != 0 {
		if packetReaderFlag&packetReaderPcapgo != 0 {
			file, err := os.Open(pcapSource)
			if err != nil {
				return nil, err
			}
			return pcapgo.NewReader(file)
		}
		return pcap.OpenOffline(pcapSource)
	}
	if packetReaderFlag&packetReaderPcapgo != 0 {
		return pcapgo.NewEthernetHandle(pcapSource)
	}
	return pcap.OpenLive(pcapSource, snaplen, (packetReaderFlag&packetReaderPromisc != 0), pcap.BlockForever)
}
func ClosePacketReader(packetReader PacketReader, file *os.File) {
	switch handle := packetReader.(type) {
	case *pcap.Handle:
		handle.Close()
	case *pcapgo.EthernetHandle:
		handle.Close()
	}
	if file != nil {
		file.Close()
	}
}

func (fk FlowKey) Serialize() [flowKeySize]byte {
	var buf [flowKeySize]byte
	copy(buf[0:], fk.sourceIPAddress)
	copy(buf[16:], fk.destinationIPAddress)
	binary.BigEndian.PutUint16(buf[32:], fk.sourceTransportPort)
	binary.BigEndian.PutUint16(buf[34:], fk.destinationTransportPort)
	buf[36] = fk.protocolIdentifier
	buf[37] = fk.ipClassOfService
	return buf
}

func (fk FlowKey) hash(maxFlows uint64) uint64 {
	flowKeyBuffer := fk.Serialize()
	flowKeyFnv64a := fnv64a(flowKeyBuffer[:])
	if maxFlows == 0 {
		return flowKeyFnv64a
	}
	return (flowKeyFnv64a % maxFlows)
}

func (fk FlowKey) Equal(another FlowKey) bool {
	if !fk.sourceIPAddress.Equal(another.sourceIPAddress) ||
		!fk.destinationIPAddress.Equal(another.destinationIPAddress) ||
		fk.sourceTransportPort != another.sourceTransportPort ||
		fk.destinationTransportPort != another.destinationTransportPort ||
		fk.protocolIdentifier != fk.protocolIdentifier ||
		fk.ipClassOfService != fk.ipClassOfService {
		return false
	}
	return true
}

func (fk FlowKey) String() string {
	return fmt.Sprintf("sIP:%s, dIP:%s, sPort:%d, dPort:%d, Proto:%d, TOS:%d",
		fk.sourceIPAddress.String(), fk.destinationIPAddress.String(),
		fk.sourceTransportPort, fk.destinationTransportPort, fk.protocolIdentifier,
		fk.ipClassOfService)
}

func (f *Flow) SerializeNetflow5(buf []byte, baseTime time.Time) {
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
}

func (f *Flow) String() string {
	return fmt.Sprintf("%s, tcpFlag:%d, octets:%d, packet:%d, start:%s, end:%s",
		f.key.String(), f.tcpControlBits, f.octetDeltaCount, f.packetDeltaCount,
		f.start.String(), f.end.String())
}

func tcpFlag(t *layers.TCP) uint16 {
	var f uint16
	if t.FIN {
		f |= tcpControlBitsFIN
	}
	if t.SYN {
		f |= tcpControlBitsSYN
	}
	if t.RST {
		f |= tcpControlBitsRST
	}
	if t.PSH {
		f |= tcpControlBitsPSH
	}
	if t.ACK {
		f |= tcpControlBitsACK
	}
	if t.URG {
		f |= tcpControlBitsURG
	}
	if t.ECE {
		f |= tcpControlBitsECE
	}
	if t.CWR {
		f |= tcpControlBitsCWR
	}
	if t.NS {
		f |= tcpControlBitsNS
	}
	return f
}

func updateFlowCache(newFlow Flow, cachedFlow *Flow, flowChan chan Flow, fcp FlowCacheParameters) uint8 {
	flowEndReason := uint8(0)
	if !cachedFlow.key.Equal(newFlow.key) { // hash collision: flow is not same with same id
		flowEndReason = flowEndReasonLackOfResources
	} else if uint64(newFlow.end.Sub(cachedFlow.end).Seconds()) > fcp.idleTimeout {
		flowEndReason = flowEndReasonIdleTimeout
	} else { // update flow
		cachedFlow.packetDeltaCount++
		cachedFlow.octetDeltaCount += newFlow.octetDeltaCount
		cachedFlow.end = newFlow.end
		cachedFlow.tcpControlBits |= newFlow.tcpControlBits
		if cachedFlow.tcpControlBits&tcpControlBitsFIN > 0 {
			flowEndReason = flowEndReasonEndOfFlow
		} else if uint64(cachedFlow.end.Sub(cachedFlow.start).Seconds()) > fcp.activeTimeout {
			flowEndReason = flowEndReasonActiveTimeout
		}
	}
	if flowEndReason > 0 {
		flowChan <- *cachedFlow // expire
		switch flowEndReason {
		case flowEndReasonLackOfResources, flowEndReasonIdleTimeout:
			*cachedFlow = newFlow
		case flowEndReasonEndOfFlow, flowEndReasonActiveTimeout:
			cachedFlow.packetDeltaCount = 0
		}
	}
	return flowEndReason
}

func processPacket(packetReader PacketReader, flowCache FlowCache, pp ParserParameters, ms *MeterStatistics, flowChan chan Flow, fcp FlowCacheParameters) (time.Time, error) {
	var flow Flow
	packetData, ci, err := packetReader.ZeroCopyReadPacketData()
	if err != nil {
		return ci.Timestamp, err
	}
	ms.observedPacketTotalCount++
	ms.observedOctetTotalCount += uint64(ci.Length)
	err = pp.parser.DecodeLayers(packetData, &pp.decoded)
	err = flow.DecodeFromBytes(packetData, ci, pp)
	if err != nil {
		ms.ignoredPacketTotalCount++
		ms.ignoredOctetTotalCount += uint64(ci.Length)
	}
	flowCache.Store(flow, flow.key.hash(fcp.maxFlows), flowChan, fcp)
	return ci.Timestamp, err
}

func main() {
	//defer profile.Start().Stop()
	ifName := flag.String("ifName", "", "name of interface for packet captureing")
	pcapFileName := flag.String("pcapFileName", "", "name of pcap file")
	isPromisc := flag.Bool("isPromisc", false, "isPromisc")
	usePcapgo := flag.Bool("usePcapgo", false, "pcapgo")
	storeMap := flag.Bool("storeMap", false, "store Flow to Map data strecture")
	snaplen := flag.Uint64("snaplen", defaultSnapLength, "snaplen")
	destination := flag.String("destination", "", "Destination for exporting")
	packetNumber := flag.Uint64("packetNumber", 0, "Maximum number of reading packets")
	maxFlows := flag.Uint64("maxFlows", defaultFlowNumber, "Maximum number of cached flows ")
	flowActiveTimeout := flag.Uint64("flowActiveTimeout", defaultFlowActiveTimeout, "flowActiveTimeout")
	flowIdleTimeout := flag.Uint64("flowIdleTimeout", defaultFlowIdleTimeout, "flowIdleTimeout")
	flag.Parse()

	var packetSource string
	var isOffline bool
	if *ifName != "" {
		packetSource = *ifName
		isOffline = false
	} else if *pcapFileName != "" {
		packetSource = *pcapFileName
		isOffline = true
	}
	if packetSource == "" {
		err := fmt.Errorf("packet source is not specified.")
		log.Fatal(err)
	}

	var file *os.File
	var packetReaderFlag uint8
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6
	var ms MeterStatistics
	pp := ParserParameters{
		parser:  gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp, &icmp4, &icmp6),
		decoded: []gopacket.LayerType{},
		eth:     &eth,
		dot1q:   &dot1q,
		ip4:     &ip4,
		ip6:     &ip6,
		tcp:     &tcp,
		udp:     &udp,
		icmp4:   &icmp4,
		icmp6:   &icmp6,
	}
	fcp := FlowCacheParameters{
		maxFlows:      *maxFlows,
		activeTimeout: *flowActiveTimeout,
		idleTimeout:   *flowIdleTimeout,
	}
	if isOffline {
		packetReaderFlag |= packetReaderOffline
	}
	if *isPromisc {
		packetReaderFlag |= packetReaderPromisc
	}
	if *usePcapgo {
		packetReaderFlag |= packetReaderPcapgo
	}
	packetReader, err := NewPacketReader(packetReaderFlag, packetSource, int32(*snaplen), file)
	if err != nil {
		log.Fatal(err)
	}

	defer ClosePacketReader(packetReader, file)

	flowCache := NewFlowCache(*storeMap, *maxFlows)

	flowChan := make(chan Flow)
	finished := make(chan bool)
	defer close(finished)

	firstPacketTime, err := processPacket(packetReader, flowCache, pp, &ms, flowChan, fcp)
	go netflow5(*destination, firstPacketTime, flowChan, finished)
	for *packetNumber == 0 || ms.observedPacketTotalCount < *packetNumber {
		_, err = processPacket(packetReader, flowCache, pp, &ms, flowChan, fcp)
		if err == io.EOF {
			break
		}
	}
	flowCache.ExpireAll(flowChan, fcp)
	close(flowChan)
	_ = <-finished
}

func packetDataToFlow(packetData []byte, ci *gopacket.CaptureInfo, decoded *[]gopacket.LayerType, eth *layers.Ethernet, dot1q *layers.Dot1Q, ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP, icmp4 *layers.ICMPv4, icmp6 *layers.ICMPv6) (Flow, error) {
	flow := Flow{
		packetDeltaCount: 1,
		octetDeltaCount:  uint64(ci.Length),
		start:            ci.Timestamp,
		end:              ci.Timestamp,
	}
	for _, typ := range *decoded {
		switch typ {
		//case layers.LayerTypeEthernet:
		case layers.LayerTypeIPv4:
			if ip4.FragOffset > 0 {
				return flow, fmt.Errorf("Fragment")
			}
			flow.key.sourceIPAddress = ip4.SrcIP
			flow.key.destinationIPAddress = ip4.DstIP
			flow.key.protocolIdentifier = uint8(ip4.Protocol)
			flow.key.ipClassOfService = ip4.TOS
		case layers.LayerTypeIPv6:
			flow.key.sourceIPAddress = ip6.SrcIP
			flow.key.destinationIPAddress = ip6.DstIP
			flow.key.protocolIdentifier = uint8(ip6.NextHeader)
			flow.key.ipClassOfService = ip6.TrafficClass
		case layers.LayerTypeTCP:
			flow.key.sourceTransportPort = uint16(tcp.SrcPort)
			flow.key.destinationTransportPort = uint16(tcp.DstPort)
			flow.tcpControlBits = tcpFlag(tcp)
		case layers.LayerTypeUDP:
			flow.key.sourceTransportPort = uint16(udp.SrcPort)
			flow.key.destinationTransportPort = uint16(udp.DstPort)
		case layers.LayerTypeICMPv4:
			flow.key.sourceTransportPort = uint16(0)
			flow.key.destinationTransportPort = uint16(icmp4.TypeCode)
		case layers.LayerTypeICMPv6:
			flow.key.sourceTransportPort = uint16(0)
			flow.key.destinationTransportPort = uint16(icmp6.TypeCode)
		}
	}
	return flow, nil
}

func netflow5(destination string, firstPacketTime time.Time, flowChan chan Flow, finished chan bool) {
	conn, err := net.Dial("udp", destination)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	defer conn.Close()
	var buf [exportBufferSize]byte

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
			flow.SerializeNetflow5(buf[netflow5HeaderSize+flowCount*netflow5RecordSize:],
				firstPacketTime)
			flowCount++
			totalFlowCount++
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
