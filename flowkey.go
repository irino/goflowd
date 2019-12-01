package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
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
	flowLabeIPv6             uint32
	fragmentIdentification   uint32
	sourceTransportPort      uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	destinationTransportPort uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	icmpTypeCode             uint16 // filling DST_PORT field when version is 1, 5, 7, 8
	vlanId                   uint16
	sourceMacAddress         [6]byte
	destinationMacAddress    [6]byte
	protocolIdentifier       uint8 // NetFlow version 1, 5, 7, 8(FullFlow)
	ipClassOfService         uint8 // NetFlow version 1, 5, 7, 8(FullFlow)
	ipVersion                uint8
}

func copyIP(ip net.IP) net.IP {
	// To save space, try and only use 4 bytes
	if x := ip.To4(); x != nil {
		ip = x
	}
	dst := make(net.IP, len(ip))
	copy(dst, ip)
	return dst
}
func (src FlowKey) Copy(dst *FlowKey) {
	dst.sourceIPAddress = copyIP(src.sourceIPAddress)
	dst.destinationIPAddress = copyIP(src.destinationIPAddress)
	dst.flowLabeIPv6 = src.flowLabeIPv6
	dst.fragmentIdentification = src.fragmentIdentification
	dst.sourceTransportPort = src.sourceTransportPort
	dst.destinationTransportPort = src.destinationTransportPort
	dst.icmpTypeCode = src.icmpTypeCode
	dst.vlanId = src.vlanId
	dst.sourceMacAddress = src.sourceMacAddress
	dst.destinationMacAddress = src.destinationMacAddress
	dst.protocolIdentifier = src.protocolIdentifier
	dst.ipClassOfService = src.ipClassOfService
	dst.ipVersion = src.ipVersion
}

// Serialize seriaizes (encodes) to byte array from FlowKey
func (fk FlowKey) Serialize() []byte {
	buf := make([]byte, 63)
	copy(buf[0:], fk.sourceIPAddress)
	copy(buf[16:], fk.destinationIPAddress)
	binary.BigEndian.PutUint32(buf[32:], fk.flowLabeIPv6)
	binary.BigEndian.PutUint32(buf[36:], fk.fragmentIdentification)
	binary.BigEndian.PutUint16(buf[40:], fk.sourceTransportPort)
	binary.BigEndian.PutUint16(buf[42:], fk.destinationTransportPort)
	binary.BigEndian.PutUint16(buf[44:], fk.icmpTypeCode)
	binary.BigEndian.PutUint16(buf[46:], fk.vlanId)
	copy(buf[48:], fk.sourceMacAddress[0:6])
	copy(buf[54:], fk.destinationMacAddress[0:6])
	buf[60] = fk.protocolIdentifier
	buf[61] = fk.ipClassOfService
	buf[62] = fk.ipVersion
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
		fk.flowLabeIPv6 != another.flowLabeIPv6 ||
		fk.fragmentIdentification != another.flowLabeIPv6 ||
		fk.sourceTransportPort != another.sourceTransportPort ||
		fk.destinationTransportPort != another.destinationTransportPort ||
		fk.icmpTypeCode != another.icmpTypeCode ||
		fk.vlanId != another.vlanId ||
		!bytes.Equal(fk.sourceMacAddress[:], another.sourceMacAddress[:]) ||
		!bytes.Equal(fk.destinationMacAddress[:], another.destinationMacAddress[:]) ||
		fk.protocolIdentifier != another.protocolIdentifier ||
		fk.ipClassOfService != another.ipClassOfService ||
		fk.ipVersion != another.ipVersion {
		return false
	}
	return true
}

func (fk FlowKey) String() string {
	return fmt.Sprintf("sIP:%s, dIP:%s, flowlabel: %d, fragmentID: %d, sPort:%d, dPort:%d, icmp:%d, vlan:%d, Proto:%d, TOS:%d, ipver:%d",
		fk.sourceIPAddress.String(), fk.destinationIPAddress.String(),
		fk.flowLabeIPv6, fk.fragmentIdentification,
		fk.sourceTransportPort, fk.destinationTransportPort, fk.icmpTypeCode, fk.vlanId,
		fk.protocolIdentifier, fk.ipClassOfService, fk.ipVersion)
}
