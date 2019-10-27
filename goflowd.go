package main

import (
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	//"github.com/pkg/profile"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"time"
)

//Information Element List
const (
	Reserved = iota
	octetDeltaCount
	packetDeltaCount
	deltaFlowCount
	protocolIdentifier
	ipClassOfService
	tcpControlBits
	sourceTransportPort
	sourceIPv4Address
	sourceIPv4PrefixLength
	ingressInterface
	destinationTransportPort
	destinationIPv4Address
	destinationIPv4PrefixLength
	egressInterface
	ipNextHopIPv4Address
	bgpSourceAsNumber
	bgpDestinationAsNumber
	bgpNextHopIPv4Address
	postMCastPacketDeltaCount
	postMCastOctetDeltaCount
	flowEndSysUpTime
	flowStartSysUpTime
	postOctetDeltaCount
	postPacketDeltaCount
	minimumIpTotalLength
	maximumIpTotalLength
	sourceIPv6Address
	destinationIPv6Address
	sourceIPv6PrefixLength
	destinationIPv6PrefixLength
	flowLabelIPv6
	icmpTypeCodeIPv4
	igmpType
	samplingInterval
	samplingAlgorithm
	flowActiveTimeout
	flowIdleTimeout
	engineType
	engineId
	exportedOctetTotalCount
	exportedMessageTotalCount
	exportedFlowRecordTotalCount
	ipv4RouterSc
	sourceIPv4Prefix
	destinationIPv4Prefix
	mplsTopLabelType
	mplsTopLabelIPv4Address
	samplerId
	samplerMode
	samplerRandomInterval
	classId
	minimumTTL
	maximumTTL
	fragmentIdentification
	postIpClassOfService
	sourceMacAddress
	postDestinationMacAddress
	vlanId
	postVlanId
	ipVersion
	flowDirection
	ipNextHopIPv6Address
	bgpNextHopIPv6Address
	ipv6ExtensionHeaders //64
	_
	_
	_
	_
	_
	mplsTopLabelStackSection //70
	mplsLabelStackSection2
	mplsLabelStackSection3
	mplsLabelStackSection4
	mplsLabelStackSection5
	mplsLabelStackSection6
	mplsLabelStackSection7
	mplsLabelStackSection8
	mplsLabelStackSection9
	mplsLabelStackSection10
	destinationMacAddress
	postSourceMacAddress
	interfaceName
	interfaceDescription
	samplerName
	octetTotalCount
	packetTotalCount
	flagsAndSamplerId
	fragmentOffset
	forwardingStatus
	mplsVpnRouteDistinguisher
	mplsTopLabelPrefixLength
	srcTrafficIndex
	dstTrafficIndex
	applicationDescription
	applicationId
	applicationName
	_
	postIpDiffServCodePoint //98
	multicastReplicationFactor
	className
	classificationEngineId
	layer2packetSectionOffset
	layer2packetSectionSize
	layer2packetSectionData //104
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	bgpNextAdjacentAsNumber //128
	bgpPrevAdjacentAsNumber
	exporterIPv4Address
	exporterIPv6Address
	droppedOctetDeltaCount
	droppedPacketDeltaCount
	droppedOctetTotalCount
	droppedPacketTotalCount
	flowEndReason
	commonPropertiesId
	observationPointId
	icmpTypeCodeIPv6
	mplsTopLabelIPv6Address
	lineCardId
	portId
	meteringProcessId
	exportingProcessId
	templateId
	wlanChannelId
	wlanSSID
	flowId
	observationDomainId
	flowStartSeconds
	flowEndSeconds
	flowStartMilliseconds
	flowEndMilliseconds
	flowStartMicroseconds
	flowEndMicroseconds
	flowStartNanoseconds
	flowEndNanoseconds
	flowStartDeltaMicroseconds
	flowEndDeltaMicroseconds
	systemInitTimeMilliseconds
	flowDurationMilliseconds
	flowDurationMicroseconds
	observedFlowTotalCount
	ignoredPacketTotalCount
	ignoredOctetTotalCount
	notSentFlowTotalCount
	notSentPacketTotalCount
	notSentOctetTotalCount
	destinationIPv6Prefix
	sourceIPv6Prefix
	postOctetTotalCount
	postPacketTotalCount
	flowKeyIndicator
	postMCastPacketTotalCount
	postMCastOctetTotalCount
	icmpTypeIPv4
	icmpCodeIPv4
	icmpTypeIPv6
	icmpCodeIPv6
	udpSourcePort
	udpDestinationPort
	tcpSourcePort
	tcpDestinationPort
	tcpSequenceNumber
	tcpAcknowledgementNumber
	tcpWindowSize
	tcpUrgentPointer
	tcpHeaderLength
	ipHeaderLength
	totalLengthIPv4
	payloadLengthIPv6
	ipTTL
	nextHeaderIPv6
	mplsPayloadLength
	ipDiffServCodePoint
	ipPrecedence
	fragmentFlags
	octetDeltaSumOfSquares
	octetTotalSumOfSquares
	mplsTopLabelTTL
	mplsLabelStackLength
	mplsLabelStackDepth
	mplsTopLabelExp
	ipPayloadLength
	udpMessageLength
	isMulticast
	ipv4IHL
	ipv4Options
	tcpOptions
	paddingOctets
	collectorIPv4Address
	collectorIPv6Address
	exportInterface
	exportProtocolVersion
	exportTransportProtocol
	collectorTransportPort
	exporterTransportPort
	tcpSynTotalCount
	tcpFinTotalCount
	tcpRstTotalCount
	tcpPshTotalCount
	tcpAckTotalCount
	tcpUrgTotalCount
	ipTotalLength
	postNATSourceIPv4Address
	postNATDestinationIPv4Address
	postNAPTSourceTransportPort
	postNAPTDestinationTransportPort
	natOriginatingAddressRealm
	natEvent
	initiatorOctets
	responderOctets
	firewallEvent
	ingressVRFID
	egressVRFID
	VRFname
	postMplsTopLabelExp
	tcpWindowScale
	biflowDirection
	ethernetHeaderLength
	ethernetPayloadLength
	ethernetTotalLength
	dot1qVlanId
	dot1qPriority
	dot1qCustomerVlanId
	dot1qCustomerPriority
	metroEvcId
	metroEvcType
	pseudoWireId
	pseudoWireType
	pseudoWireControlWord
	ingressPhysicalInterface
	egressPhysicalInterface
	postDot1qVlanId
	postDot1qCustomerVlanId
	ethernetType
	postIpPrecedence
	collectionTimeMilliseconds
	exportSctpStreamId
	maxExportSeconds
	maxFlowEndSeconds
	messageMD5Checksum
	messageScope
	minExportSeconds
	minFlowStartSeconds
	opaqueOctets
	sessionScope
	maxFlowEndMicroseconds
	maxFlowEndMilliseconds
	maxFlowEndNanoseconds
	minFlowStartMicroseconds
	minFlowStartMilliseconds
	minFlowStartNanoseconds
	collectorCertificate
	exporterCertificate
	dataRecordsReliability
	observationPointType
	newConnectionDeltaCount
	connectionSumDurationSeconds
	connectionTransactionId
	postNATSourceIPv6Address
	postNATDestinationIPv6Address
	natPoolId
	natPoolName
	anonymizationFlags
	anonymizationTechnique
	informationElementIndex
	p2pTechnology
	tunnelTechnology
	encryptedTechnology
	basicList
	subTemplateList
	subTemplateMultiList
	bgpValidityState
	IPSecSPI
	greKey
	natType
	initiatorPackets
	responderPackets
	observationDomainName
	selectionSequenceId
	selectorId
	informationElementId
	selectorAlgorithm
	samplingPacketInterval
	samplingPacketSpace
	samplingTimeInterval
	samplingTimeSpace
	samplingSize
	samplingPopulation
	samplingProbability
	dataLinkFrameSize
	ipHeaderPacketSection
	ipPayloadPacketSection
	dataLinkFrameSection
	mplsLabelStackSection
	mplsPayloadPacketSection
	selectorIdTotalPktsObserved
	selectorIdTotalPktsSelected
	absoluteError
	relativeError
	observationTimeSeconds
	observationTimeMilliseconds
	observationTimeMicroseconds
	observationTimeNanoseconds
	digestHashValue
	hashIPPayloadOffset
	hashIPPayloadSize
	hashOutputRangeMin
	hashOutputRangeMax
	hashSelectedRangeMin
	hashSelectedRangeMax
	hashDigestOutput
	hashInitialiserValue
	selectorName
	upperCILimit
	lowerCILimit
	confidenceLevel
	informationElementDataType
	informationElementDescription
	informationElementName
	informationElementRangeBegin
	informationElementRangeEnd
	informationElementSemantics
	informationElementUnits
	privateEnterpriseNumber
	virtualStationInterfaceId
	virtualStationInterfaceName
	virtualStationUUID
	virtualStationName
	layer2SegmentId
	layer2OctetDeltaCount
	layer2OctetTotalCount
	ingressUnicastPacketTotalCount
	ingressMulticastPacketTotalCount
	ingressBroadcastPacketTotalCount
	egressUnicastPacketTotalCount
	egressBroadcastPacketTotalCount
	monitoringIntervalStartMilliSeconds
	monitoringIntervalEndMilliSeconds
	portRangeStart
	portRangeEnd
	portRangeStepSize
	portRangeNumPorts
	staMacAddress
	staIPv4Address
	wtpMacAddress
	ingressInterfaceType
	egressInterfaceType
	rtpSequenceNumber
	userName
	applicationCategoryName
	applicationSubCategoryName
	applicationGroupName
	originalFlowsPresent
	originalFlowsInitiated
	originalFlowsCompleted
	distinctCountOfSourceIPAddress
	distinctCountOfDestinationIPAddress
	distinctCountOfSourceIPv4Address
	distinctCountOfDestinationIPv4Address
	distinctCountOfSourceIPv6Address
	distinctCountOfDestinationIPv6Address
	valueDistributionMethod
	rfc3550JitterMilliseconds
	rfc3550JitterMicroseconds
	rfc3550JitterNanoseconds
	dot1qDEI
	dot1qCustomerDEI
	flowSelectorAlgorithm
	flowSelectedOctetDeltaCount
	flowSelectedPacketDeltaCount
	flowSelectedFlowDeltaCount
	selectorIDTotalFlowsObserved
	selectorIDTotalFlowsSelected
	samplingFlowInterval
	samplingFlowSpacing
	flowSamplingTimeInterval
	flowSamplingTimeSpacing
	hashFlowDomain
	transportOctetDeltaCount
	transportPacketDeltaCount
	originalExporterIPv4Address
	originalExporterIPv6Address
	originalObservationDomainId
	intermediateProcessId
	ignoredDataRecordTotalCount
	dataLinkFrameType
	sectionOffset
	sectionExportedOctets
	dot1qServiceInstanceTag
	dot1qServiceInstanceId
	dot1qServiceInstancePriority
	dot1qCustomerSourceMacAddress
	dot1qCustomerDestinationMacAddress
	postLayer2OctetDeltaCount
	postMCastLayer2OctetDeltaCount
	postLayer2OctetTotalCount
	postMCastLayer2OctetTotalCount
	minimumLayer2TotalLength
	maximumLayer2TotalLength
	droppedLayer2OctetDeltaCount
	droppedLayer2OctetTotalCount
	ignoredLayer2OctetTotalCount
	notSentLayer2OctetTotalCount
	layer2OctetDeltaSumOfSquares
	layer2OctetTotalSumOfSquares
	layer2FrameDeltaCount
	layer2FrameTotalCount
	pseudoWireDestinationIPv4Address
	ignoredLayer2FrameTotalCount
	mibObjectValueInteger
	mibObjectValueOctetString
	mibObjectValueOID
	mibObjectValueBits
	mibObjectValueIPAddress
	mibObjectValueCounter
	mibObjectValueGauge
	mibObjectValueTimeTicks
	mibObjectValueUnsigned
	mibObjectValueTable
	mibObjectValueRow
	mibObjectIdentifier
	mibSubIdentifier
	mibIndexIndicator
	mibCaptureTimeSemantics
	mibContextEngineID
	mibContextName
	mibObjectName
	mibObjectDescription
	mibObjectSyntax
	mibModuleName
	mobileIMSI
	mobileMSISDN
	httpStatusCode
	sourceTransportPortsLimit
	httpRequestMethod
	httpRequestHost
	httpRequestTarget
	httpMessageVersion
	natInstanceID
	internalAddressRealm
	externalAddressRealm
	natQuotaExceededEvent
	natThresholdEvent
	httpUserAgent
	httpContentType
	httpReasonPhrase
	maxSessionEntries
	maxBIBEntries
	maxEntriesPerUser
	maxSubscribers
	maxFragmentsPendingReassembly
	addressPoolHighThreshold
	addressPoolLowThreshold
	addressPortMappingHighThreshold
	addressPortMappingLowThreshold
	addressPortMappingPerUserHighThreshold
	globalAddressMappingHighThreshold
	vpnIdentifier
	bgpCommunity
	bgpSourceCommunityList
	bgpDestinationCommunityList
	bgpExtendedCommunity
	bgpSourceExtendedCommunityList
	bgpDestinationExtendedCommunityList
	bgpLargeCommunity
	bgpSourceLargeCommunityList
	bgpDestinationLargeCommunityList
)

const ( // goflowd parameters
	defaultMaxFlows          = 65536
	defaultSnapLength        = 1518
	exportBufferSize         = 1472
	netflow5HeaderSize       = 24
	netflow5RecordSize       = 48
	flowKeySize              = 38
	defaultFlowActiveTimeout = 1800
	defaultFlowIdleTimeout   = 15
)

// https://www.iana.org/assignments/ipfix/ipfix.xml 6:tcpControlBits
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

// https://www.iana.org/assignments/ipfix/ipfix.xml 136:flowEndReason
const (
	flowEndReasonIdleTimeout     uint8 = 0x01
	flowEndReasonActiveTimeout   uint8 = 0x02
	flowEndReasonEndOfFlow       uint8 = 0x03
	flowEndReasonForceEnd        uint8 = 0x04
	flowEndReasonLackOfResources uint8 = 0x05
)

// goflowd packetReader options
const (
	packetReaderOffline     uint8 = 0x01
	packetReaderPromiscuous uint8 = 0x02
	packetReaderPcapgo      uint8 = 0x04
)

// caclcurate hash key of FlowKey
func fnv32a(b []byte) uint32 {
	hash := fnv.New32a()
	hash.Write(b)
	return hash.Sum32()
}

// goflowd fixed flowkeys
type FlowKey struct {
	sourceIPAddress          net.IP // NetFlow version 1, 5, 7, 8(FullFlow)
	destinationIPAddress     net.IP // NetFlow version 1, 5, 7, 8(FullFlow)
	sourceTransportPort      uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	destinationTransportPort uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	icmpTypeCode             uint16 // filling DST_PORT field when version is 1, 5, 7, 8
	protocolIdentifier       uint8  // NetFlow version 1, 5, 7, 8(FullFlow)
	ipClassOfService         uint8  // NetFlow version 1, 5, 7, 8(FullFlow)
	flowLabeIPv6             uint32
	fragmentIdentification   uint32
	sourceMacAddress         [6]byte
	destinationMacAddress    [6]byte
	vlanId                   uint16
	ipVersion                uint8
}

// Serialize seriaizes (encodes) to byte array from FlowKey
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

// hash provides hash number (uint32) from FlowKey
func (fk FlowKey) hash(maxFlows uint32) uint32 {
	flowKeyBuffer := fk.Serialize()
	flowKeyFnv32a := fnv32a(flowKeyBuffer[:])
	if maxFlows == 0 {
		return flowKeyFnv32a
	}
	return (flowKeyFnv32a % maxFlows)
}

// Equal compares a FlowKey to another FlowKey
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

// goflowd flow parameters
type Flow struct {
	key              FlowKey
	nonKey           FlowKey
	tcpControlBits   uint16 // NetFlow version 1, 5, 7
	flowEndReason    uint8
	octetDeltaCount  uint64
	packetDeltaCount uint64
	start            time.Time
	end              time.Time
}

func NewFlow(pp ParserParameters, cacheFields []CacheField, ci gopacket.CaptureInfo) Flow {
	var flow Flow
	isEthernet, isDot1Q, isIPv4, isIPv6, isTCP, isUDP, isICMPv4, isICMPv6 := false, false, false, false, false, false, false, false
	for _, layerType := range pp.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			isEthernet = true
		case layers.LayerTypeDot1Q:
			isDot1Q = true
		case layers.LayerTypeIPv4:
			isIPv4 = true
		case layers.LayerTypeIPv6:
			isIPv6 = true
		case layers.LayerTypeTCP:
			isTCP = true
		case layers.LayerTypeUDP:
			isUDP = true
		case layers.LayerTypeICMPv4:
			isICMPv4 = true
		case layers.LayerTypeICMPv6:
			isICMPv6 = true
		}
	}
	for _, cacheField := range cacheFields {
		var key *FlowKey
		if cacheField.IsFlowKey {
			key = &flow.key
		} else {
			key = &flow.nonKey
		}
		switch cacheField.IeId {
		case protocolIdentifier: //4
			if isIPv4 {
				key.protocolIdentifier = uint8(pp.ip4.Protocol)
			} else if isIPv6 {
				key.protocolIdentifier = uint8(pp.ip6.NextHeader)
			}
		case ipClassOfService, postIpClassOfService: //5, 55
			if isIPv4 {
				key.ipClassOfService = uint8(pp.ip4.TOS)
			} else if isIPv6 {
				key.ipClassOfService = uint8(pp.ip6.TrafficClass)
			}
		case tcpControlBits: //6
			if isTCP {
				flow.tcpControlBits = tcpFlag(pp.tcp)
			}
		case sourceTransportPort: //7
			if isTCP {
				key.sourceTransportPort = uint16(pp.tcp.SrcPort)
			} else if isUDP {
				key.sourceTransportPort = uint16(pp.udp.SrcPort)
			}
		case sourceIPv4Address: //8
			if isIPv4 {
				key.sourceIPAddress = pp.ip4.SrcIP
			}
		case destinationTransportPort: //11
			if isTCP {
				key.destinationTransportPort = uint16(pp.tcp.DstPort)
			} else if isUDP {
				key.destinationTransportPort = uint16(pp.udp.DstPort)
			}
		case destinationIPv4Address: //12
			if isIPv4 {
				key.destinationIPAddress = pp.ip4.DstIP
			}
		case sourceIPv6Address: //27
			if isIPv6 {
				key.sourceIPAddress = pp.ip6.SrcIP
			}
		case destinationIPv6Address: //28
			if isIPv6 {
				key.destinationIPAddress = pp.ip6.DstIP
			}
		case flowLabelIPv6: //31
			if isIPv6 {
				key.flowLabeIPv6 = pp.ip6.FlowLabel
			}
		case icmpTypeCodeIPv4: //32
			if isICMPv4 {
				key.icmpTypeCode = uint16(pp.icmp4.TypeCode)
			}
		case fragmentIdentification: //54
			if isIPv4 {
				key.fragmentIdentification = uint32(pp.ip4.Id)
			}
		case sourceMacAddress, postSourceMacAddress: //56
			if isEthernet {
				copy(key.sourceMacAddress[0:6], pp.eth.SrcMAC)
			}
		case postDestinationMacAddress, destinationMacAddress: //57
			if isEthernet {
				copy(key.destinationMacAddress[0:6], pp.eth.DstMAC)
			}
		case vlanId, postVlanId, dot1qVlanId, postDot1qVlanId: //58, 59, 243, 254
			if isDot1Q {
				key.vlanId = pp.dot1q.VLANIdentifier
			}
		case ipVersion: //60
			if isIPv4 {
				key.ipVersion = 4
			} else if isIPv6 {
				key.ipVersion = 6
			}
		case icmpTypeCodeIPv6: //139
			if isICMPv6 {
				key.icmpTypeCode = uint16(pp.icmp6.TypeCode)
			}
		case icmpTypeIPv4: //176
			if isICMPv4 {
				key.icmpTypeCode = uint16(pp.icmp4.TypeCode) & 0xff00
			}
		case icmpCodeIPv4: //177
			if isICMPv4 {
				key.icmpTypeCode = uint16(pp.icmp4.TypeCode) & 0x00ff
			}
		case icmpTypeIPv6: //178
			if isICMPv6 {
				key.icmpTypeCode = uint16(pp.icmp6.TypeCode) & 0xff00
			}
		case icmpCodeIPv6: //179
			if isICMPv6 {
				key.icmpTypeCode = uint16(pp.icmp6.TypeCode) & 0x00ff
			}
		case udpSourcePort: //180
			if isUDP {
				key.sourceTransportPort = uint16(pp.udp.SrcPort)
			}
		case udpDestinationPort: //181
			if isUDP {
				key.destinationTransportPort = uint16(pp.udp.DstPort)
			}
		case tcpSourcePort: //182
			if isTCP {
				key.sourceTransportPort = uint16(pp.tcp.SrcPort)
			}
		case tcpDestinationPort: //183
			if isTCP {
				key.destinationTransportPort = uint16(pp.tcp.DstPort)
			}
		case nextHeaderIPv6: //193
			if isIPv6 {
				key.protocolIdentifier = uint8(pp.ip6.NextHeader)
			}
		case ipDiffServCodePoint: //195
			if isIPv4 {
				key.ipClassOfService = uint8(pp.ip4.TOS) >> 2
			} else if isIPv6 {
				key.ipClassOfService = uint8(pp.ip6.TrafficClass) >> 2
			}
		case ipPrecedence: //196
			if isIPv4 {
				key.ipClassOfService = uint8(pp.ip4.TOS) >> 5
			} else if isIPv6 {
				key.ipClassOfService = uint8(pp.ip6.TrafficClass) >> 5
			}
		}
	}
	flow.packetDeltaCount = 1
	flow.octetDeltaCount = uint64(ci.Length)
	flow.start, flow.end = ci.Timestamp, ci.Timestamp
	return flow
}

// DecodeFromBytes decodes byte slice to pointer of Flow struct
func (flow *Flow) DecodeFromBytes(packetData []byte, ci gopacket.CaptureInfo, pp ParserParameters) error {
	flow.packetDeltaCount = 1
	flow.octetDeltaCount = uint64(ci.Length)
	flow.start, flow.end = ci.Timestamp, ci.Timestamp
	for _, typ := range pp.decoded {
		switch typ {
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

func (f *Flow) String() string {
	return fmt.Sprintf("%s, tcpFlag:%d, octets:%d, packet:%d, start:%s, end:%s",
		f.key.String(), f.tcpControlBits, f.octetDeltaCount, f.packetDeltaCount,
		f.start.String(), f.end.String())
}

func (cachedFlow *Flow) update(newFlow Flow, fcp CacheParameters) uint8 {
	flowEndReason := uint8(0)
	if !cachedFlow.key.Equal(newFlow.key) { // hash collision: flow is not same with same id
		flowEndReason = flowEndReasonLackOfResources
	} else if uint32(newFlow.end.Sub(cachedFlow.end).Seconds()) > fcp.idleTimeout {
		flowEndReason = flowEndReasonIdleTimeout
	} else { // update flow
		cachedFlow.packetDeltaCount++
		cachedFlow.octetDeltaCount += newFlow.octetDeltaCount
		cachedFlow.end = newFlow.end
		cachedFlow.tcpControlBits |= newFlow.tcpControlBits
		if cachedFlow.tcpControlBits&tcpControlBitsFIN > 0 {
			flowEndReason = flowEndReasonEndOfFlow
		} else if uint32(cachedFlow.end.Sub(cachedFlow.start).Seconds()) > fcp.activeTimeout {
			flowEndReason = flowEndReasonActiveTimeout
		}
	}
	return flowEndReason
}
func (cachedFlow *Flow) reset(newFlow Flow, flowEndReason uint8) {
	switch flowEndReason {
	case flowEndReasonLackOfResources, flowEndReasonIdleTimeout:
		*cachedFlow = newFlow
	case flowEndReasonEndOfFlow, flowEndReasonActiveTimeout:
		cachedFlow.packetDeltaCount = 0
	}
}

func updateCacheData(newFlow Flow, cachedFlow *Flow, flowChan chan Flow, fcp CacheParameters) uint8 {
	flowEndReason := uint8(0)
	if !cachedFlow.key.Equal(newFlow.key) { // hash collision: flow is not same with same id
		flowEndReason = flowEndReasonLackOfResources
	} else if uint32(newFlow.end.Sub(cachedFlow.end).Seconds()) > fcp.idleTimeout {
		flowEndReason = flowEndReasonIdleTimeout
	} else { // update flow
		cachedFlow.packetDeltaCount++
		cachedFlow.octetDeltaCount += newFlow.octetDeltaCount
		cachedFlow.end = newFlow.end
		cachedFlow.tcpControlBits |= newFlow.tcpControlBits
		if cachedFlow.tcpControlBits&tcpControlBitsFIN > 0 {
			flowEndReason = flowEndReasonEndOfFlow
		} else if uint32(cachedFlow.end.Sub(cachedFlow.start).Seconds()) > fcp.activeTimeout {
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

// ParserParameters has parameters relating gopacket.NewDecodingLayerParser
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

type CacheData interface {
	StoreFlow(flow Flow, fcp CacheParameters, destinations []Destination, destinationIndexes []int) uint8
	ExpireAll(flowChan chan Flow, fcp CacheParameters)
}

type SliceTypeCacheData []Flow
type MapTypeCacheData map[uint32]Flow

func NewCacheData(storeMap bool, maxFlows uint32) CacheData {
	if storeMap {
		return MapTypeCacheData(make(map[uint32]Flow, maxFlows))
	}
	return SliceTypeCacheData(make([]Flow, maxFlows))
}

func (sliceTypeCacheData SliceTypeCacheData) StoreFlow(flow Flow, fcp CacheParameters, destinations []Destination, destinationIndexes []int) uint8 {
	flowEndReason := uint8(0)
	flowHashId := flow.key.hash(fcp.maxFlows)
	if sliceTypeCacheData[flowHashId].packetDeltaCount > 0 { //flow exists in sliceTypeCacheData
		flowEndReason = (&sliceTypeCacheData[flowHashId]).update(flow, fcp)
		if flowEndReason > 0 {
			//expire
			for i := 0; i < len(destinations); i++ {
				(&destinations[i]).exportNetFlowV5(sliceTypeCacheData[flowHashId])
			}
			//reset
			(&sliceTypeCacheData[flowHashId]).reset(flow, flowEndReason)
		}
	} else { //flow doesn't exist in sliceTypeCacheData
		sliceTypeCacheData[flowHashId] = flow
	}
	return flowEndReason
}
func (sliceTypeCacheData SliceTypeCacheData) ExpireAll(flowChan chan Flow, fcp CacheParameters) {
	for id := uint32(0); id < fcp.maxFlows; id++ {
		if sliceTypeCacheData[id].packetDeltaCount > 0 {
			flowChan <- sliceTypeCacheData[id]
		}
	}
}

func (mapTypeCacheData MapTypeCacheData) StoreFlow(flow Flow, fcp CacheParameters, destinations []Destination, destinationIndexes []int) uint8 {
	flowEndReason := uint8(0)
	flowHashId := flow.key.hash(fcp.maxFlows)
	f, ok := mapTypeCacheData[flowHashId]
	if ok { //flow exists in mapTypeCacheData
		flowEndReason = (&f).update(flow, fcp)
		if flowEndReason > 0 {
			//expire
			for _, v := range destinationIndexes {
				(&destinations[v]).exportNetFlowV5(f)
			}
			//reset
			(&f).reset(flow, flowEndReason)
			if flowEndReason == flowEndReasonEndOfFlow || flowEndReason == flowEndReasonActiveTimeout {
				delete(mapTypeCacheData, flowHashId)
			}
		}
		mapTypeCacheData[flowHashId] = f // update
	} else { //flow doesn't exist in mapTypeCacheData
		mapTypeCacheData[flowHashId] = flow
	}
	return flowEndReason
}
func (mapTypeCacheData MapTypeCacheData) ExpireAll(flowChan chan Flow, fcp CacheParameters) {
	for id, f := range mapTypeCacheData {
		flowChan <- f
		delete(mapTypeCacheData, id)
	}
}

type CacheParameters struct {
	maxFlows      uint32
	activeTimeout uint32
	idleTimeout   uint32
}

type Cache struct {
	Index                int
	Name                 string
	ExportingProcessName []string
	Parameters           CacheParameters
	Data                 CacheData
	Fields               []CacheField
	destinationIndexes   []int
}

func (c Cache) String() string {
	s := fmt.Sprintf("Index: %d, Name, %s ", c.Index, c.Name)
	for i, v := range c.ExportingProcessName {
		s += fmt.Sprintf("ExportingProcessName[%d]: %s ", i, v)
	}
	for i, v := range c.destinationIndexes {
		s += fmt.Sprintf("destinationIndexes[%d]: %d ", i, v)
	}
	s += "\n"
	return s
}

func (cache *Cache) associateDestination(destinations []Destination) {
	for _, epName := range cache.ExportingProcessName {
		for _, v := range destinations {
			if epName == v.ExportingProcessName {
				cache.destinationIndexes = append(cache.destinationIndexes, v.Index)
			}
		}
	}
}

func (cache *IETFIpfixPsamp_Ipfix_Cache) NewCache(ianaIEsUint map[uint16]IERecord, ianaIEsString map[string]IERecord) Cache {
	mapImpl := false
	maxFlows := uint32(defaultMaxFlows)
	activeTimeout := uint32(defaultFlowActiveTimeout)
	idleTimeout := uint32(defaultFlowIdleTimeout)
	cacheFields := []CacheField{}
	if cache.MapImplementation != nil {
		mapImpl = *cache.MapImplementation
	}
	if cache.TimeoutCache != nil && cache.TimeoutCache.CacheLayout != nil {
		for _, field := range cache.TimeoutCache.CacheLayout.CacheField {
			cacheField, err := NewCacheField(field.IeId, field.IeLength, field.IeName, bool(field.IsFlowKey), field.Name, ianaIEsUint, ianaIEsString)
			if err == nil {
				cacheFields = append(cacheFields, cacheField)
			}
			if cache.TimeoutCache.MaxFlows != nil {
				maxFlows = *cache.TimeoutCache.MaxFlows
			}
			if cache.TimeoutCache.ActiveTimeout != nil {
				activeTimeout = *cache.TimeoutCache.ActiveTimeout
			}
			if cache.TimeoutCache.IdleTimeout != nil {
				idleTimeout = *cache.TimeoutCache.IdleTimeout
			}
		}
	} else if cache.NaturalCache != nil && cache.NaturalCache.CacheLayout != nil {
		for _, field := range cache.NaturalCache.CacheLayout.CacheField {
			cacheField, err := NewCacheField(field.IeId, field.IeLength, field.IeName, bool(field.IsFlowKey), field.Name, ianaIEsUint, ianaIEsString)
			if err == nil {
				cacheFields = append(cacheFields, cacheField)
			}
			if cache.NaturalCache.MaxFlows != nil {
				maxFlows = *cache.NaturalCache.MaxFlows
			}
			if cache.NaturalCache.ActiveTimeout != nil {
				activeTimeout = *cache.NaturalCache.ActiveTimeout
			}
			if cache.NaturalCache.IdleTimeout != nil {
				idleTimeout = *cache.NaturalCache.IdleTimeout
			}
		}
	} else if cache.PermanentCache != nil && cache.PermanentCache.CacheLayout != nil {
		for _, field := range cache.PermanentCache.CacheLayout.CacheField {
			cacheField, err := NewCacheField(field.IeId, field.IeLength, field.IeName, bool(field.IsFlowKey), field.Name, ianaIEsUint, ianaIEsString)
			if err == nil {
				cacheFields = append(cacheFields, cacheField)
			}
			if cache.PermanentCache.MaxFlows != nil {
				maxFlows = *cache.PermanentCache.MaxFlows
			}
			activeTimeout = 0
			idleTimeout = 0
		}
	} else if cache.ImmediateCache != nil && cache.ImmediateCache.CacheLayout != nil {
		for _, field := range cache.ImmediateCache.CacheLayout.CacheField {
			cacheField, err := NewCacheField(field.IeId, field.IeLength, field.IeName, bool(field.IsFlowKey), field.Name, ianaIEsUint, ianaIEsString)
			if err == nil {
				cacheFields = append(cacheFields, cacheField)
			}
			maxFlows = 0
		}
	}
	sort.SliceStable(cacheFields,
		func(i int, j int) bool {
			if cacheFields[i].FieldName == cacheFields[j].FieldName {
				return cacheFields[i].IeId < cacheFields[j].IeId
			}
			return cacheFields[i].FieldName < cacheFields[j].FieldName
		})
	var c Cache
	c.Name = ""
	if cache.Name != nil {
		c.Name = *cache.Name
	}
	c.ExportingProcessName = cache.ExportingProcess

	c.Parameters.maxFlows = maxFlows
	c.Parameters.activeTimeout = activeTimeout
	c.Parameters.idleTimeout = idleTimeout
	c.Data = NewCacheData(mapImpl, maxFlows)
	c.Fields = cacheFields
	c.destinationIndexes = []int{}
	return c
}

func (ipfix *IETFIpfixPsamp_Ipfix) NewCaches(ianaIEsUint map[uint16]IERecord, ianaIEsString map[string]IERecord) []Cache {
	caches := []Cache{}
	for _, cache := range ipfix.Cache {
		caches = append(caches, cache.NewCache(ianaIEsUint, ianaIEsString))
	}
	sort.SliceStable(caches,
		func(i int, j int) bool {
			return caches[i].Name < caches[j].Name
		})
	for i, _ := range caches {
		caches[i].Index = i
	}
	return caches
}

// PacketLayers is real entity of packet headers for gopacket.NewDecodingLayerParser
type PacketLayers struct {
	eth   layers.Ethernet
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6
}

type PacketReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

const (
	SelectAll = iota
	CountBasedSampling
	TimeBasedSampling
)

type Selector struct {
	Index                      int
	Name                       string
	SelectionProcessName       string
	CacheName                  string
	Algorithm                  uint16
	Interval                   uint32
	Space                      uint32
	NextSampleStartPacketCount uint64
	NextSampleEndPacketCount   uint64
	NextSampleStartTime        time.Time
	NextSampleEndTime          time.Time
	TotalPacketCount           uint64
	LastPacketTime             time.Time
	CacheIndex                 int
}

func (selector Selector) String() string {
	s := fmt.Sprintf("Index: %d, Name: %s, SelectorocessName: %s, Algorithm: %d, Interval: %d, Space: %d, CacheIndex: %d\n", selector.Index, selector.Name, selector.SelectionProcessName, selector.Algorithm, selector.Interval, selector.Space, selector.CacheIndex)
	return s
}

func (selector *Selector) associateCache(caches []Cache) {
	for _, v := range caches {
		if selector.CacheName == v.Name {
			selector.CacheIndex = v.Index
			break
		}
	}
}

func (s *Selector) selectPacket(packetTime time.Time) bool {
	if s.Algorithm == SelectAll {
		return true
	} else if s.Algorithm == CountBasedSampling {
		if s.TotalPacketCount == 0 {
			s.NextSampleStartPacketCount = 1
			s.NextSampleEndPacketCount = s.NextSampleStartPacketCount + uint64(s.Interval)
		}
		s.TotalPacketCount++
		if s.NextSampleStartPacketCount <= s.TotalPacketCount && s.TotalPacketCount < s.NextSampleEndPacketCount {
			return true
		} else {
			if s.NextSampleEndPacketCount <= s.TotalPacketCount {
				s.NextSampleStartPacketCount = s.NextSampleEndPacketCount + uint64(s.Space)
				s.NextSampleEndPacketCount = s.NextSampleStartPacketCount + uint64(s.Interval)
			}
			return false
		}
	} else if s.Algorithm == TimeBasedSampling {
		if s.TotalPacketCount == 0 {
			s.NextSampleStartTime = packetTime
			s.NextSampleEndTime = s.NextSampleStartTime.Add(time.Duration(s.Interval))
		}
		s.TotalPacketCount++
		s.LastPacketTime = packetTime
		if s.NextSampleStartTime.Equal(s.LastPacketTime) || (s.NextSampleStartTime.After(s.LastPacketTime) && s.NextSampleEndTime.Before(s.LastPacketTime)) {
			return true
		} else {
			if s.NextSampleEndTime.Equal(s.LastPacketTime) || s.NextSampleEndTime.After(s.LastPacketTime) {
				s.NextSampleStartTime = s.NextSampleEndTime.Add(time.Duration(s.Space))
				s.NextSampleEndTime = s.NextSampleStartTime.Add(time.Duration(s.Interval))
			}
			return false
		}
	}
	return false
}
func (selector *IETFIpfixPsamp_Ipfix_SelectionProcess_Selector) NewSelector(spName string, cacheName string) Selector {
	var s Selector
	s.Name = ""
	s.SelectionProcessName = spName
	s.CacheName = cacheName
	if selector.Name != nil {
		s.Name = *selector.Name
	}
	if selector.SelectAll == true {
		s.Algorithm = SelectAll
	} else if selector.SampCountBased != nil {
		s.Algorithm = CountBasedSampling
		if selector.SampCountBased.PacketInterval != nil {
			s.Interval = *selector.SampCountBased.PacketInterval
		} else {
			s.Interval = 1
		}
		if selector.SampCountBased.PacketSpace != nil {
			s.Space = *selector.SampCountBased.PacketSpace
		} else {
			s.Space = 0
		}
	} else if selector.SampTimeBased != nil {
		s.Algorithm = TimeBasedSampling
		if selector.SampTimeBased.TimeInterval != nil {
			s.Interval = *selector.SampTimeBased.TimeInterval
		} else {
			s.Interval = 1
		}
		if selector.SampTimeBased.TimeSpace != nil {
			s.Space = *selector.SampTimeBased.TimeSpace
		} else {
			s.Space = 0
		}
	}
	return s
}

func (ipfix *IETFIpfixPsamp_Ipfix) NewSelectors() []Selector {
	selectors := []Selector{}
	for spName, sp := range ipfix.SelectionProcess {
		for _, selector := range sp.Selector {
			selectors = append(selectors, selector.NewSelector(spName, *sp.Cache))
		}
	}
	sort.SliceStable(selectors,
		func(i int, j int) bool {
			return selectors[i].Name < selectors[j].Name
		})
	for i, _ := range selectors {
		selectors[i].Index = i
	}
	return selectors
}

type PacketSource struct {
	Index                uint32
	Name                 string
	reader               PacketReader
	file                 *os.File
	SelectionProcessName []string
	SelectorIndexes      []int
}

func (ps PacketSource) String() string {
	s := fmt.Sprintf("Index: %d, Name, %s ", ps.Index, ps.Name)
	for i, v := range ps.SelectionProcessName {
		s += fmt.Sprintf("SelectionProcessName[%d]: %s ", i, v)
	}
	for i, v := range ps.SelectorIndexes {
		s += fmt.Sprintf("SelectionIndexes[%d]: %d ", i, v)
	}
	s += "\n"
	return s

}

func (packetSource *PacketSource) associateSlelector(selectors []Selector) {
	for _, spName := range packetSource.SelectionProcessName {
		for _, v := range selectors {
			if spName == v.SelectionProcessName {
				packetSource.SelectorIndexes = append(packetSource.SelectorIndexes, v.Index)
				break
			}
		}
	}
}

func (packetSource PacketSource) processPacket(selectors []Selector, caches []Cache, destinations []Destination, pp ParserParameters) error {
	packetData, ci, err := packetSource.reader.ZeroCopyReadPacketData()
	if err != nil {
		log.Printf("%s\n", err)
		return err
	}
	err = pp.parser.DecodeLayers(packetData, &pp.decoded)
	for _, v := range packetSource.SelectorIndexes {
		if !(&selectors[v]).selectPacket(ci.Timestamp) {
			continue
		}
		cache := caches[selectors[v].CacheIndex]
		flow := NewFlow(pp, cache.Fields, ci)
		cache.Data.StoreFlow(flow, cache.Parameters, destinations, cache.destinationIndexes)
	}
	return nil
}

func (packetSource PacketSource) processPackets(selectors []Selector, caches []Cache, destinations []Destination, pp ParserParameters) {
	for {
		if err := packetSource.processPacket(selectors, caches, destinations, pp); err != nil {
			break
		}
	}

}
func (op *IETFIpfixPsamp_Ipfix_ObservationPoint) NewPacketReader(pcapSource string, file **os.File) (PacketReader, error) {
	if op.OfflineFile != nil {
		if op.PcapgoImplementation != nil {
			var err error
			*file, err = os.Open(pcapSource)
			if err != nil {
				return nil, err
			}
			return pcapgo.NewReader(*file)
		}
		return pcap.OpenOffline(pcapSource)
	}
	if op.PcapgoImplementation != nil {
		return pcapgo.NewEthernetHandle(pcapSource)
	}
	snapLength := int32(defaultSnapLength)
	if op.SnapLength != nil {
		snapLength = *op.SnapLength
	}
	return pcap.OpenLive(pcapSource, snapLength, (op.Promiscuous != nil), pcap.BlockForever)
}

func (op *IETFIpfixPsamp_Ipfix_ObservationPoint) NewPacketSource(ifName string, spName []string) PacketSource {
	var packetSource PacketSource
	var err error
	packetSource.SelectionProcessName = spName
	packetSource.reader, err = op.NewPacketReader(ifName, &packetSource.file)
	if err != nil {
		log.Fatal(err)
	}
	packetSource.Name = ifName
	return packetSource
}

func (ipfix *IETFIpfixPsamp_Ipfix) NewPacketSources() []PacketSource {
	packetSources := []PacketSource{}
	for _, op := range ipfix.ObservationPoint {
		if op.OfflineFile != nil {
			packetSources = append(packetSources, op.NewPacketSource(*op.OfflineFile, op.SelectionProcess))
			continue // if offlineFile is specified, IfName is not processed.
		}
		for _, v := range op.IfName {
			packetSources = append(packetSources, op.NewPacketSource(v, op.SelectionProcess))
		}
	}
	return packetSources
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

// cache field is a type to store real entity for cacheField configuration
type CacheField struct {
	IeId               uint16
	IeLength           uint16
	IeEnterpriseNumber uint32
	IsFlowKey          bool
	FieldName          string // for sort
}

// NewCacheFiled retruns new CacheField from common parameters IETFIpfixPsamp_Ipfix_Cache_ImmediateCache_*_CacheField struct
func NewCacheField(IeId *uint16, IeLength *uint16, IeName *string, IsFlowKey bool, Name *string, ianaIEsUint map[uint16]IERecord, ianaIEsString map[string]IERecord) (CacheField, error) {
	var cacheField CacheField
	var ie IERecord
	if IeName != nil {
		ie = ianaIEsString[*IeName]
	} else if IeId != nil {
		ie = ianaIEsUint[*IeId]
	} else {
		return cacheField, fmt.Errorf("Can't find Information Element")
	}
	cacheField.IeId = ie.ElementId
	// if data type of Information Eement
	if ie.DataType == "octetArray" || ie.DataType == "string" || ie.DataTypeSemantics == "list" {
		if IeLength != nil {
			cacheField.IeLength = *IeLength
		} else {
			return cacheField, fmt.Errorf("Length for Information Element whose dataType is octetArray or string is not specified.\n")
		}
	} else if ie.Group == "flowCounter" && IeLength != nil {
		cacheField.IeLength = *IeLength
	} else {
		switch ie.DataType {
		case "signed64", "unsigned64", "float64", "dateTimeMilliseconds", "dateTimeMicroseconds", "dateTimeNanoseconds":
			cacheField.IeLength = 8
		case "signed32", "unsigned32", "float32", "ipv4Address", "dateTimeSeconds":
			cacheField.IeLength = 4
		case "signed16", "unsigned16":
			cacheField.IeLength = 2
		case "signed8", "unsigned8", "boolean":
			cacheField.IeLength = 1
		case "ipv6Address":
			cacheField.IeLength = 16
		case "macAddress":
			cacheField.IeLength = 6
		}
	}
	cacheField.IeEnterpriseNumber = 0
	cacheField.IsFlowKey = IsFlowKey
	if Name != nil {
		cacheField.FieldName = *Name
	} else {
		cacheField.FieldName = ""
	}
	return cacheField, nil
}

type Destination struct {
	Index                int
	Name                 string
	ExportingProcessName string
	Protocol             string
	IPAddress            string
	IP                   net.IP
	Port                 uint16
	Version              uint16
	BaseTime             time.Time
	BufferSize           uint32
	buffer               []byte
	connection           net.Conn
	UsedBufferSize       uint32
	TotalFlowCount       uint32
}

func (d Destination) String() string {
	s := fmt.Sprintf("Index: %d, Name: %s, ExportingProcess: %s, Protocol: %s, IPAddress: %s, IP: %s, Port: %d, Version:%d, BaseTime: %s, BufferSize: %d, UsedBufferSize: %s, TotalFlowCount:%s\n",
		d.Index, d.Name, d.ExportingProcessName, d.Protocol, d.IPAddress, d.IP.String(), d.Port, d.Version, d.BaseTime.String(), d.BufferSize, d.UsedBufferSize, d.TotalFlowCount)
	return s
}

func (destination *IETFIpfixPsamp_Ipfix_ExportingProcess_Destination) NewDestination(epName string) Destination {
	var dest Destination

	dest.ExportingProcessName = epName
	dest.Protocol = "udp"
	dest.Port = uint16(4739)
	dest.IPAddress = ""
	dest.Version = uint16(10)
	dest.BufferSize = uint32(exportBufferSize)
	dest.UsedBufferSize = 0
	dest.Name = ""

	if destination.Name != nil {
		dest.Name = *destination.Name
	}
	if destination.TcpExporter != nil {
		dest.Protocol = "tcp"
		if destination.TcpExporter.DestinationIPAddress != nil {
			dest.IPAddress = *destination.TcpExporter.DestinationIPAddress
		} else {
			fmt.Errorf("destinatinoIPAddress is not specified\n")
		}
		if destination.TcpExporter.DestinationPort != nil {
			dest.Port = *destination.TcpExporter.DestinationPort
		}
		if destination.TcpExporter.IpfixVersion != nil {
			dest.Version = *destination.TcpExporter.IpfixVersion
		}
		if destination.TcpExporter.SendBufferSize != nil {
			dest.BufferSize = *destination.TcpExporter.SendBufferSize
		} else {
			dest.BufferSize = exportBufferSize
		}
	} else if destination.UdpExporter != nil {
		dest.Protocol = "udp"
		if destination.UdpExporter != nil {
			dest.IPAddress = *destination.UdpExporter.DestinationIPAddress
		} else {
			fmt.Errorf("destinatinoIPAddress is not specified\n")
		}
		if destination.UdpExporter.DestinationPort != nil {
			dest.Port = *destination.UdpExporter.DestinationPort
		}
		if destination.UdpExporter.IpfixVersion != nil {
			dest.Version = *destination.UdpExporter.IpfixVersion
		}
	} else {
		fmt.Errorf("Unsported export protocol\n")
	}
	dest.connection, _ = net.Dial(dest.Protocol,
		fmt.Sprintf("%s:%d", dest.IPAddress, dest.Port))
	dest.buffer = make([]byte, dest.BufferSize)
	dest.BaseTime = time.Now()
	return dest
}

func (ipfix *IETFIpfixPsamp_Ipfix) NewDestinations() []Destination {
	destinations := []Destination{}
	for epName, ep := range ipfix.ExportingProcess {
		for _, destination := range ep.Destination {
			destinations = append(destinations, destination.NewDestination(epName))
		}
	}
	sort.SliceStable(destinations,
		func(i int, j int) bool {
			return destinations[i].Name < destinations[j].Name
		})
	for i, _ := range destinations {
		destinations[i].Index = i
	}
	return destinations
}

func main() {
	//defer profile.Start().Stop()
	config := flag.String("config", "", "configuration file")
	flag.Parse()

	jsonString, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal("Read file: ", err)
	}

	ipfix := &IETFIpfixPsamp_Ipfix{}
	if err := Unmarshal(jsonString, ipfix); err != nil {
		panic(fmt.Sprintf("Cannot unmarshal JSON: %v", err))
	}

	destinations := ipfix.NewDestinations()
	ianaIEsUint, ianaIEsString := readIANAIERecords()
	caches := ipfix.NewCaches(ianaIEsUint, ianaIEsString)
	for i := 0; i < len(caches); i++ {
		(&caches[i]).associateDestination(destinations)
	}
	selectors := ipfix.NewSelectors()
	for i := 0; i < len(selectors); i++ {
		(&selectors[i]).associateCache(caches)
	}
	packetSources := ipfix.NewPacketSources()
	for i := 0; i < len(packetSources); i++ {
		(&packetSources[i]).associateSlelector(selectors)
	}

	var pl PacketLayers
	pp := ParserParameters{
		parser:  gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &pl.eth, &pl.dot1q, &pl.ip4, &pl.ip6, &pl.tcp, &pl.udp, &pl.icmp4, &pl.icmp6),
		decoded: []gopacket.LayerType{},
		eth:     &pl.eth,
		dot1q:   &pl.dot1q,
		ip4:     &pl.ip4,
		ip6:     &pl.ip6,
		tcp:     &pl.tcp,
		udp:     &pl.udp,
		icmp4:   &pl.icmp4,
		icmp6:   &pl.icmp6,
	}

	for _, v := range packetSources {
		v.processPackets(selectors, caches, destinations, pp)
	}

}

func (destination *Destination) exportNetFlowV5(flow Flow) {
	if destination.UsedBufferSize == 0 &&
		(destination.UsedBufferSize+netflow5HeaderSize <= destination.BufferSize) {
		binary.BigEndian.PutUint16(destination.buffer[0:], uint16(5))  // NetFlow v5 Header constant value
		destination.buffer[20] = uint8(0)                              // engine type
		destination.buffer[21] = uint8(0)                              // engine id
		binary.BigEndian.PutUint16(destination.buffer[22:], uint16(0)) // sample rate
		destination.UsedBufferSize = netflow5HeaderSize
	}
	if destination.UsedBufferSize+netflow5RecordSize <= destination.BufferSize {
		flow.SerializeNetflow5(destination.buffer[destination.UsedBufferSize:],
			destination.BaseTime)
		destination.UsedBufferSize += netflow5RecordSize
	}
	if destination.UsedBufferSize+netflow5RecordSize > destination.BufferSize {
		flowCount := uint16((destination.BufferSize - netflow5HeaderSize) / netflow5RecordSize)
		destination.TotalFlowCount += uint32(flowCount)
		binary.BigEndian.PutUint16(destination.buffer[2:], flowCount)
		binary.BigEndian.PutUint32(destination.buffer[4:],
			uint32(flow.end.Sub(destination.BaseTime).Nanoseconds()/int64(time.Millisecond)))
		binary.BigEndian.PutUint32(destination.buffer[8:], uint32(flow.end.Unix()))
		binary.BigEndian.PutUint32(destination.buffer[12:],
			uint32(flow.end.UnixNano()-flow.end.Unix()*int64(time.Nanosecond)))
		binary.BigEndian.PutUint32(destination.buffer[16:], destination.TotalFlowCount)
		destination.connection.Write(destination.buffer[:destination.UsedBufferSize]) // UDP Send
		destination.UsedBufferSize = netflow5HeaderSize
	}
}

type IERecord struct {
	Name              string `xml:"name"`
	DataType          string `xml:"dataType"`
	DataTypeSemantics string `xml:"dataTypeSemantics"`
	Group             string `xml:"group"`
	ElementId         uint16 `xml:"elementId"`
}

func readIANAIERecords() (map[uint16]IERecord, map[string]IERecord) {
	ieRecordsUint16Map := map[uint16]IERecord{}
	ieRecordsStringMap := map[string]IERecord{}
	xmlFile, err := os.Open("ipfix.xml")
	if err != nil {
		log.Fatal(err)
	}
	defer xmlFile.Close()
	decoder := xml.NewDecoder(xmlFile)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		switch se := token.(type) {
		case xml.StartElement:
			if se.Name.Local == "record" {
				var ieRecord IERecord
				decoder.DecodeElement(&ieRecord, &se)
				if ieRecord.Name != "" && ieRecord.ElementId > 0 {
					ieRecordsUint16Map[ieRecord.ElementId] = ieRecord
					ieRecordsStringMap[ieRecord.Name] = ieRecord
				}
			}
		}
	}
	return ieRecordsUint16Map, ieRecordsStringMap
}
