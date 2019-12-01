package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io/ioutil"
	"log"
)

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
