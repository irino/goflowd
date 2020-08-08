package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"os"
)

type PacketReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type PacketSource struct {
	Name                 string
	reader               PacketReader
	file                 *os.File
	selectorsMaps        map[string][]*Selector
	SelectionProcessName []string
	selectorPointers     []*Selector
	observationDomainId  uint32
}

// ParserParameters has parameters relating gopacket.NewDecodingLayerParser
type ParserParameters struct {
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	udp     *layers.UDP
	sctp    *layers.SCTP
	icmp4   *layers.ICMPv4
	icmp6   *layers.ICMPv6
	decoded []gopacket.LayerType
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

func (ps PacketSource) String() string {
	s := fmt.Sprintf("Name, %s ", ps.Name)
	for i, v := range ps.SelectionProcessName {
		s += fmt.Sprintf("SelectionProcessName[%d]: %s ", i, v)
	}
	for i, v := range ps.selectorPointers {
		s += fmt.Sprintf("selectorPointers[%d]: %p: %s ", i, v, (*v).String())
	}
	s += "\n"
	return s

}

func (packetSource *PacketSource) associateSlelector(selectors []Selector) {
	for _, spName := range packetSource.SelectionProcessName {
		for i := 0; i < len(selectors); i++ {
			if spName == selectors[i].SelectionProcessName {
				packetSource.selectorPointers = append(packetSource.selectorPointers, &selectors[i])
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
	for i := 0; i < len(packetSource.selectorPointers); i++ {
		if !packetSource.selectorPointers[i].selectPacket(ci.Timestamp) {
			continue
		}
		cache := *packetSource.selectorPointers[i].cachePointer
		flow := NewFlow(pp, cache.Fields, ci)
		cache.storeData(flow, destinations, packetSource)
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
