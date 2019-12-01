package main

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
)

type CacheData []Flow

func NewCacheData(maxFlows uint32) CacheData {
	return CacheData(make([]Flow, maxFlows))
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
	destinationPointers  []*Destination
	dataRecordSize       uint16
}

func (cache Cache) serializeTemplateSet(version uint16) ([]byte, uint16, uint16) {
	// Set Header: 4 bytes
	// Template Record Header: 4 bytes
	// Information Elements: 4 bytes x number of Information Elements
	templateid := uint16(256 + cache.Index)
	length := uint16(4 + 4 + len(cache.Fields)*4)
	buffer := make([]byte, length)
	if version == 10 {
		binary.BigEndian.PutUint16(buffer[0:], 2) // Set ID = 2: Template Set for IPFIX
	} else if version == 9 {
		binary.BigEndian.PutUint16(buffer[0:], 0) // Set ID = 0: Template Set for NetFlow v9
	}
	binary.BigEndian.PutUint16(buffer[2:], length)
	binary.BigEndian.PutUint16(buffer[4:], templateid)
	binary.BigEndian.PutUint16(buffer[6:], uint16(len(cache.Fields)))
	for i := 0; i < len(cache.Fields); i++ {
		binary.BigEndian.PutUint16(buffer[8+i*4:], cache.Fields[i].IeId)
		binary.BigEndian.PutUint16(buffer[10+i*4:], cache.Fields[i].IeLength)
	}
	return buffer, length, templateid
}

func (cache Cache) storeData(flow Flow, destinations []Destination, ps PacketSource) uint8 {
	flowEndReason := uint8(0)
	flowHashId := flow.key.hash(cache.Parameters.maxFlows)
	if cache.Data[flowHashId].packetDeltaCount > 0 { //flow exists in CacheData
		flowEndReason = (&cache.Data[flowHashId]).update(flow, cache.Parameters)
		if flowEndReason > 0 { //expire
			for i := 0; i < len(destinations); i++ {
				switch destinations[i].Version {
				case 5:
					(&destinations[i]).exportNetFlowV5(cache.Data[flowHashId])
				case 10:
					(&destinations[i]).exportIPFIX(cache.Data[flowHashId], ps.observationDomainId, cache)
				}
			}
			(&cache.Data[flowHashId]).reset(flow, flowEndReason) //reset
		}
	} else { //flow doesn't exist in CacheData
		flow.Copy(&cache.Data[flowHashId])
	}
	return flowEndReason
}

func (cache Cache) String() string {
	s := fmt.Sprintf("Index: %d, Name, %s ", cache.Index, cache.Name)
	for i, v := range cache.ExportingProcessName {
		s += fmt.Sprintf("ExportingProcessName[%d]: %s ", i, v)
	}
	for i, v := range cache.destinationPointers {
		s += fmt.Sprintf("destinationPointers[%d]: %p: %s ", i, v, (*v).String())
	}
	s += "\n"
	return s
}

func (cache *Cache) associateDestination(destinations []Destination) {
	for _, epName := range cache.ExportingProcessName {
		for i := 0; i < len(destinations); i++ {
			if epName == destinations[i].ExportingProcessName {
				cache.destinationPointers = append(cache.destinationPointers, &destinations[i])
			}
		}
	}
}
