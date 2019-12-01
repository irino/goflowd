package main

import (
    "fmt"
)


// cache field is a type to store real entity for cacheField configuration
type CacheField struct {
	IeId               uint16
	IeLength           uint16
	IeEnterpriseNumber uint32
	FieldName          string // for sort
	IsFlowKey          bool
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
