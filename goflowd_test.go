package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestEncodeAndDecodeNetFlowV5DataRecord(t *testing.T) {
	//Test data
	boot := time.Date(2019, time.August, 18, 15, 30, 0, 0, time.UTC)
	start := time.Date(2019, time.August, 18, 15, 31, 50, 0, time.UTC)
	end := time.Date(2019, time.August, 18, 15, 32, 51, 0, time.UTC)
	flowkey := FlowKey{
		sourceIPAddress:          net.IPv4(1, 2, 3, 4),
		destinationIPAddress:     net.IPv4(255, 166, 177, 188),
		sourceTransportPort:      54321,
		destinationTransportPort: 8080,
		protocolIdentifier:       6,
		ipClassOfService:         46,
	}
	flow := Flow{
		key:              flowkey,
		tcpControlBits:   0x0013,
		octetDeltaCount:  150000,
		packetDeltaCount: 100,
		start:            start,
		end:              end,
	}

	buf := flow.EncodeNetFlowV5DataRecord(boot)
	var nf5dr NetFlowV5DataRecord
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.BigEndian, &nf5dr); err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	fmt.Printf("sIP:%s, dIP:%s, sPort:%d, dPort:%d, proto:%d, tos:%d, tcp:%d, octet:%d, packet:%d, start:%d, end:%d,\n",
		Uint32ToIp(nf5dr.SourceIPv4Address).String(),
		Uint32ToIp(nf5dr.DestinationIPv4Address).String(),
		nf5dr.SourceTransportPort, nf5dr.DestinationTransportPort,
		nf5dr.ProtocolIdentifier, nf5dr.IpClassOfService, nf5dr.TcpControlBits,
		nf5dr.OctetDeltaCount, nf5dr.PacketDeltaCount, nf5dr.FlowStartSysUptime, nf5dr.FlowEndSysUptime,
	)
	if Uint32ToIp(nf5dr.SourceIPv4Address).String() != flowkey.sourceIPAddress.String() {
		t.Fatal("SourceIPv4Address")
	}
	if Uint32ToIp(nf5dr.DestinationIPv4Address).String() != flowkey.destinationIPAddress.String() {
		t.Fatal("DestinationIPv4Address")
	}
	if nf5dr.SourceTransportPort != flowkey.sourceTransportPort {
		t.Fatal("SourceTransportPort")
	}
	if nf5dr.DestinationTransportPort != flowkey.destinationTransportPort {
		t.Fatal("DestinationTransportPort")
	}
	if nf5dr.ProtocolIdentifier != flowkey.protocolIdentifier {
		t.Fatal("ProtocolIdentifier")
	}
	if nf5dr.IpClassOfService != flowkey.ipClassOfService {
		t.Fatal("IpClassOfService")
	}
	if nf5dr.TcpControlBits != uint8(flow.tcpControlBits&0x00ff) {
		t.Fatal("PacketDeltaCount")
	}
	if nf5dr.PacketDeltaCount != uint32(flow.packetDeltaCount&0x00000000ffffffff) {
		t.Fatal("PacketDeltaCount")
	}
	if nf5dr.OctetDeltaCount != uint32(flow.octetDeltaCount&0x00000000ffffffff) {
		t.Fatal("OctetDeltaCount")
	}
	if nf5dr.FlowStartSysUptime != 110000 {
		t.Fatal("OctetDeltaCount")
	}
	if nf5dr.FlowEndSysUptime != 171000 {
		t.Fatal("OctetDeltaCount")
	}
}
