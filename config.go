package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"time"
)

const (
	defaultMaxFlows          = 65536
	defaultSnapLength        = 1518
	exportBufferSize         = 1472
	defaultFlowActiveTimeout = 1800
	defaultFlowIdleTimeout   = 15
)

func (cache *IETFIpfixPsamp_Ipfix_Cache) NewCache(ianaIEsUint map[uint16]IERecord, ianaIEsString map[string]IERecord) Cache {
	maxFlows := uint32(defaultMaxFlows)
	activeTimeout := uint32(defaultFlowActiveTimeout)
	idleTimeout := uint32(defaultFlowIdleTimeout)
	cacheFields := []CacheField{}
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
	c.Data = NewCacheData(maxFlows)
	c.Fields = cacheFields
	c.destinationPointers = []*Destination{}
	for _, v := range c.Fields {
		c.dataRecordSize += v.IeLength
	}
	return c
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
	dest.templateRefreshTimeout = 600
	dest.optionTemplateRefreshTimeout = 600

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
		if destination.UdpExporter.TemplateRefreshTimeout != nil {
			dest.templateRefreshTimeout = *destination.UdpExporter.TemplateRefreshTimeout
		}
		if destination.UdpExporter.OptionsTemplateRefreshTimeout != nil {
			dest.optionTemplateRefreshTimeout = *destination.UdpExporter.OptionsTemplateRefreshTimeout
		}
		if destination.UdpExporter.TemplateRefreshPacket != nil {
			dest.templateRefreshPacket = *destination.UdpExporter.TemplateRefreshPacket
		}
		if destination.UdpExporter.OptionsTemplateRefreshPacket != nil {
			dest.optionTemplateRefreshPacket = *destination.UdpExporter.OptionsTemplateRefreshPacket
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
	packetSource.selectorsMaps = make(map[string][]*Selector, len(spName))
	for _, v := range spName {
		packetSource.selectorsMaps[v] = []*Selector{}
	}
	packetSource.SelectionProcessName = spName
	packetSource.selectorPointers = []*Selector{}
	packetSource.reader, err = op.NewPacketReader(ifName, &packetSource.file)
	if err != nil {
		log.Fatal(err)
	}
	packetSource.Name = ifName
	if op.ObservationDomainId != nil {
		packetSource.observationDomainId = *op.ObservationDomainId
	}
	return packetSource
}

func (selector *IETFIpfixPsamp_Ipfix_SelectionProcess_Selector) NewFilterMatch() filterMatch {
	var fm filterMatch
	ieId := uint16(0)
	if selector.FilterMatch != nil && selector.FilterMatch.Value != nil {
		fm.enable = true
	}
	if selector.FilterMatch.IeId == nil && selector.FilterMatch.IeName != nil {
		ieId = ieNameToId(*selector.FilterMatch.IeName)
	} else if selector.FilterMatch.IeId != nil {
		ieId = *selector.FilterMatch.IeId
	}
	switch ieId {
	case protocolIdentifier:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.protocolIdentifier = uint8(value)
		}
	case ipClassOfService:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.ipClassOfService = uint8(value)
		}
	case sourceTransportPort:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.sourceTransportPort = uint16(value)
		}
	case sourceIPv4Address:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.sourceTransportPort = uint16(value)
		}
	case destinationTransportPort:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.destinationTransportPort = uint16(value)
		}
	case ipVersion:
		if value, err := strconv.Atoi(*selector.FilterMatch.Value); err == nil {
			fm.key.ipVersion = uint8(value)
		}
	}
	return fm
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
	if selector.FilterMatch != nil {
		s.filterMatch = selector.NewFilterMatch()
	}
	return s
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
	return destinations
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
	return selectors
}
