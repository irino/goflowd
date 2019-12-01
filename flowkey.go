package main

import (
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
func (fk FlowKey) SerializeMin() []byte {
	buf := make([]byte, binary.Size(fk))
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
