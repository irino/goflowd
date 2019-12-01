package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"time"
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

// goflowd flow parameters
type Flow struct {
	octetDeltaCount  uint64
	packetDeltaCount uint64
	start            time.Time
	end              time.Time
	key              FlowKey
	nonKey           FlowKey
	tcpControlBits   uint16 // NetFlow version 1, 5, 7
	flowEndReason    uint8
}

func (src Flow) Copy(dst *Flow) {
	dst.octetDeltaCount = src.octetDeltaCount
	dst.packetDeltaCount = src.packetDeltaCount
	dst.start = src.start
	dst.end = src.end
	src.key.Copy(&dst.key)
	src.nonKey.Copy(&dst.nonKey)
	dst.tcpControlBits = src.tcpControlBits
	dst.flowEndReason = src.flowEndReason
}

func NewFlow(pp ParserParameters, cacheFields []CacheField, ci gopacket.CaptureInfo) Flow {
	var flow Flow
	isEthernet, isDot1Q, isIPv4, isIPv6, isTCP, isUDP, isSCTP, isICMPv4, isICMPv6 := false, false, false, false, false, false, false, false, false
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
		case layers.LayerTypeSCTP:
			isSCTP = true
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
			} else if isSCTP {
				key.sourceTransportPort = uint16(pp.sctp.SrcPort)
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
			} else if isSCTP {
				key.destinationTransportPort = uint16(pp.sctp.DstPort)
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

func (f *Flow) String() string {
	return fmt.Sprintf("key:%s, nonKey:%s, tcpFlag:%d, octets:%d, packet:%d, start:%s, end:%s",
		f.key.String(), f.nonKey.String(), f.tcpControlBits, f.octetDeltaCount,
		f.packetDeltaCount, f.start.String(), f.end.String())
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
		newFlow.Copy(cachedFlow)
	case flowEndReasonEndOfFlow, flowEndReasonActiveTimeout:
		cachedFlow.packetDeltaCount = 0
	}
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

func (f *Flow) SerializeFlowCounter(buf []byte, count uint64, length uint16) {
	switch length {
	case 8:
		binary.BigEndian.PutUint64(buf, count)
	case 7, 6, 5:
		var tmpbuf [8]byte
		binary.BigEndian.PutUint64(tmpbuf[:], count)
		copy(buf, tmpbuf[8-length:8])
	case 4:
		binary.BigEndian.PutUint32(buf, uint32(count))
	case 3:
		var tmpbuf [4]byte
		binary.BigEndian.PutUint32(tmpbuf[:], uint32(count))
		copy(buf, tmpbuf[1:4])
	case 2:
		binary.BigEndian.PutUint16(buf, uint16(count))
	case 1:
		buf[0] = uint8(count)
	}
}

func (f *Flow) SerializeDataRecord(buf []byte, baseTime time.Time, cache Cache) {
	usedBufferSize := 0
	for _, v := range cache.Fields {
		var key *FlowKey
		if v.IsFlowKey {
			key = &(f.key)
		} else {
			key = &(f.nonKey)
		}
		switch v.IeId {
		case octetDeltaCount: //1
			f.SerializeFlowCounter(buf[usedBufferSize:], f.octetDeltaCount, v.IeLength)
			usedBufferSize += int(v.IeLength)
		case packetDeltaCount: //2
			f.SerializeFlowCounter(buf[usedBufferSize:], f.packetDeltaCount, v.IeLength)
			usedBufferSize += int(v.IeLength)
		case protocolIdentifier: //4
			buf[usedBufferSize] = key.protocolIdentifier
			usedBufferSize += 1
		case ipClassOfService, postIpClassOfService, ipDiffServCodePoint, ipPrecedence: //5, 55, 195, 196
			buf[usedBufferSize] = key.ipClassOfService
			usedBufferSize += 1
		case tcpControlBits: //6
			binary.BigEndian.PutUint16(buf[usedBufferSize:], key.sourceTransportPort)
			usedBufferSize += 2
		case sourceTransportPort, udpSourcePort, tcpSourcePort: //7, 180, 182
			binary.BigEndian.PutUint16(buf[usedBufferSize:], key.sourceTransportPort)
			usedBufferSize += 2
		case sourceIPv4Address: //8
			copy(buf[usedBufferSize:], key.sourceIPAddress.To4())
			usedBufferSize += 4
		case destinationTransportPort, udpDestinationPort, tcpDestinationPort: //11, 181, 183
			binary.BigEndian.PutUint16(buf[usedBufferSize:], key.destinationTransportPort)
			usedBufferSize += 2
		case destinationIPv4Address: //12
			copy(buf[usedBufferSize:], key.destinationIPAddress.To4())
			usedBufferSize += 4
		case flowEndSysUpTime: //21
			binary.BigEndian.PutUint32(buf[usedBufferSize:], uint32(f.end.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
			usedBufferSize += 4
		case flowStartSysUpTime: //22
			binary.BigEndian.PutUint32(buf[usedBufferSize:], uint32(f.start.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
			usedBufferSize += 4
		case sourceIPv6Address: //27
			copy(buf[usedBufferSize:], key.sourceIPAddress.To16())
			usedBufferSize += 16
		case destinationIPv6Address: //28
			copy(buf[usedBufferSize:], key.destinationIPAddress.To16())
			usedBufferSize += 16
		case flowLabelIPv6: //31
			binary.BigEndian.PutUint32(buf[usedBufferSize:], key.flowLabeIPv6)
			usedBufferSize += 4
		case icmpTypeCodeIPv4, icmpTypeCodeIPv6: //32, 139
			binary.BigEndian.PutUint16(buf[usedBufferSize:], key.icmpTypeCode)
			usedBufferSize += 2
		case fragmentIdentification: //54
			binary.BigEndian.PutUint32(buf[usedBufferSize:], key.fragmentIdentification)
			usedBufferSize += 4
		case sourceMacAddress, postSourceMacAddress: //56
			copy(buf[usedBufferSize:], key.sourceMacAddress[0:6])
			usedBufferSize += 6
		case destinationMacAddress, postDestinationMacAddress: //57
			copy(buf[usedBufferSize:], key.destinationMacAddress[0:6])
			usedBufferSize += 6
		case vlanId, postVlanId, dot1qVlanId, postDot1qVlanId: //58, 59, 243, 254
			binary.BigEndian.PutUint16(buf[usedBufferSize:], key.vlanId)
			usedBufferSize += 2
		case ipVersion: //60
			buf[usedBufferSize] = key.ipVersion
			usedBufferSize += 1
		case flowStartSeconds: //150
			binary.BigEndian.PutUint32(buf[usedBufferSize:], uint32(f.start.Unix()))
			usedBufferSize += 4
		case flowEndSeconds: //151
			binary.BigEndian.PutUint32(buf[usedBufferSize:], uint32(f.end.Unix()))
			usedBufferSize += 4
		case flowStartMilliseconds: //152
			binary.BigEndian.PutUint64(buf[usedBufferSize:], uint64(f.start.UnixNano()/int64(time.Millisecond)))
			usedBufferSize += 8
		case flowEndMilliseconds: //153
			binary.BigEndian.PutUint64(buf[usedBufferSize:], uint64(f.end.UnixNano()/int64(time.Millisecond)))
			usedBufferSize += 8
		case icmpTypeIPv4, icmpTypeIPv6: //176, 178
			buf[usedBufferSize] = uint8(key.icmpTypeCode >> 8)
			usedBufferSize += 1
		case icmpCodeIPv4, icmpCodeIPv6: //177, 179
			buf[usedBufferSize] = uint8(key.icmpTypeCode & 0x00ff)
			usedBufferSize += 1
		}
	}
}
