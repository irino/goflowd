package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const ( // goflowd parameters
	netflow5HeaderSize = 24
	netflow5RecordSize = 48
	IPFIXHeaderSize    = 16
)

type Destination struct {
	Name                          string
	ExportingProcessName          string
	Protocol                      string
	IPAddress                     string
	IP                            net.IP
	Port                          uint16
	Version                       uint16
	BufferSize                    uint32
	UsedBufferSize                uint32
	DataSetStartPosition          uint32
	TotalFlowCount                uint32
	BaseTime                      time.Time
	buffer                        []byte
	connection                    net.Conn
	TemplateId                    uint16
	templateRefreshTimeout        uint32
	optionTemplateRefreshTimeout  uint32
	templateRefreshPacket         uint32
	optionTemplateRefreshPacket   uint32
	lastTemplateRefreshTime       time.Time
	lastOptionTemplateRefreshTime time.Time
}

func (d Destination) String() string {
	s := fmt.Sprintf("Name: %s, ExportingProcess: %s, Protocol: %s, IPAddress: %s, IP: %s, Port: %d, Version:%d, BaseTime: %s, BufferSize: %d, UsedBufferSize: %s, TotalFlowCount:%s\n",
		d.Name, d.ExportingProcessName, d.Protocol, d.IPAddress, d.IP.String(), d.Port, d.Version, d.BaseTime.String(), d.BufferSize, d.UsedBufferSize, d.TotalFlowCount)
	return s
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
	// header update
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

func (destination *Destination) exportIPFIX(flow Flow, odId uint32, cache Cache) {
	if destination.UsedBufferSize == 0 &&
		(destination.UsedBufferSize+IPFIXHeaderSize <= destination.BufferSize) {
		// Header
		binary.BigEndian.PutUint16(destination.buffer[0:], uint16(10)) // IPFIX Header constant value
		// Length (2-4), Export Time (4-8) and Sequence (8-12) will be filled later
		binary.BigEndian.PutUint32(destination.buffer[12:], uint32(odId))
		destination.UsedBufferSize = IPFIXHeaderSize
		// Template Set
		templateSetBuffer, tempalteSetBufferSize, templateid := cache.serializeTemplateSet(destination.Version)
		copy(destination.buffer[destination.UsedBufferSize:], templateSetBuffer)
		destination.UsedBufferSize += uint32(tempalteSetBufferSize)
		destination.DataSetStartPosition += destination.UsedBufferSize
		// Data Set Header
		binary.BigEndian.PutUint16(destination.buffer[destination.UsedBufferSize:],
			uint16(templateid))
		destination.UsedBufferSize += 4
	}

	if destination.UsedBufferSize+uint32(cache.dataRecordSize) <= destination.BufferSize {
		flow.SerializeDataRecord(destination.buffer[destination.UsedBufferSize:],
			destination.BaseTime, cache)
		destination.UsedBufferSize += uint32(cache.dataRecordSize)
	}
	if destination.UsedBufferSize+uint32(cache.dataRecordSize) > destination.BufferSize {
		dataSetLength := uint16(destination.UsedBufferSize - destination.DataSetStartPosition)
		flowCount := (dataSetLength - 4) / cache.dataRecordSize
		binary.BigEndian.PutUint16(destination.buffer[destination.DataSetStartPosition+2:],
			dataSetLength)
		// filling fields in IPFIX header
		binary.BigEndian.PutUint16(destination.buffer[2:], uint16(destination.UsedBufferSize))
		binary.BigEndian.PutUint32(destination.buffer[4:], uint32(flow.end.Unix()))
		destination.TotalFlowCount += uint32(flowCount)
		binary.BigEndian.PutUint32(destination.buffer[8:], destination.TotalFlowCount)
		destination.connection.Write(destination.buffer[:destination.UsedBufferSize]) // UDP Send
		destination.UsedBufferSize = 0                                                // reset
		destination.DataSetStartPosition = 0                                          //reset
	}
}
