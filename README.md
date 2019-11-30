# goflowd

## Sumarry
goflowd is netflow probe like [softflowd](https://github.com/irino/softflowd).
It is written by golang.  goflowd uses
[ietf-ipfix-psamp.yang](https://github.com/YangModels/yang/blob/master/standard/ietf/RFC/ietf-ipfix-psamp%402012-09-05.yang)
standarized in [RFC6728](https://tools.ietf.org/html/rfc6728) data
model for configuration. The yang model configuraiton is acheived by using [openconfig/ygot](https://github.com/openconfig/ygot).

## Execution
    ./goflowd -c config.json

## Configuration sample
Configuration file is json based.
In following sample, the packets are read from `enp0s3` interface and export flow to 192.168.1.1 port 4739. In this sample, FlowKeys are `sourceIPv4Address`, `destinationIPv4Address`, `protocolIdentifier`, `sourceTransportPort`, and `destinationTransportPort`.

If you want to use offline pcap file instead of online capture, you need to use `offlineFile": "file name"` instread of `ifName": [ "interface name" ]`.

    {
        "observationPoint": [
            {
                "name": "pcap",
                "observationDomainId": 1,
                 "ifName": [ "enp0s3" ],
                "direction": "ingress",
                "selectionProcess": [
                    "All"
                ]
            }
        ],
        "selectionProcess": [
            {   
                "name": "All",
                "selector": [
                    {
                        "name": "Select all",
                        "selectAll": [
                            null
                        ]
                    }
                ],
                "cache": "Flow cache"
            }
        ],
        "cache": [
            {
                "name": "Flow cache",
                "timeoutCache": {
                    "maxFlows": 4096,
                    "activeTimeout": 5000,
                    "idleTimeout": 10000,
                    "cacheLayout": {
                        "cacheField": [
                            {
                                "name": "Field 1",
                                "ieName": "sourceIPv4Address",
                                "isFlowKey": [
                                    null
                                ]
                            },
                            {
                                "name": "Field 2",
                                "ieName": "destinationIPv4Address",
                                "isFlowKey": [
                                    null
                                ]
                            },
                            {
                                "name": "Field 3",
                                "ieName": "protocolIdentifier",
                                "isFlowKey": [
                                    null
                                ]
                            },
                            {
                                "name": "Field 4",
                                "ieName": "sourceTransportPort",
                                "isFlowKey": [
                                    null
                                ]
                            },
                            {
                                "name": "Field 5",
                                "ieName": "destinationTransportPort",
                                "isFlowKey": [
                                    null
                                ]
                            },
                            {
                                "name": "Field 6",
                                "ieName": "flowStartMilliseconds"
                            },
                            {
                                "name": "Field 7",
                                "ieName": "flowEndMilliseconds"
                            },
                            {
                                "name": "Field 8",
                                "ieName": "octetDeltaCount"
                            },
                            {
                                "name": "Field 9",
                                "ieName": "packetDeltaCount"
                            }
                        ]
                    }
                },
                "exportingProcess": [
                    "UDP"
                ]
            }
        ],
        "exportingProcess": [
            {
                "name": "UDP",
                "destination": [
                    {
                        "name": "UDP",
                        "udpExporter": {
                            "ipfixVersion": 10,
                            "destinationPort": 4739,
                            "destinationIPAddress": "192.168.1.1"
                        }
                    }
                ]
            }
        ]
    }

## Configurable Informaiton Elements for FlowKeys
|Information Element ID|Information Element Name |
|----------------------|-------------------------|
|4                     |protocolIdentifier       |
|5                     |ipClassOfService         |
|7                     |sourceTransportPort      |
|8                     |sourceIPv4Address        |
|11                    |destinationTransportPort |
|12                    |destinationIPv4Address   |
|27                    |sourceIPv6Address        |
|28                    |destinationIPv6Address   | 
|31                    |flowLabelIPv6            |
|32                    |icmpTypeCodeIPv4         |
|54                    |fragmentIdentification   |
|56                    |sourceMacAddress         |
|57                    |postDestinationMacAddress|
|58                    |vlanId                   |
|60                    |ipVersion                |
|139                   |icmpTypeCodeIPv6         |
|176                   |icmpTypeIPv4             |
|177                   |icmpCodeIPv4             |
|178                   |icmpTypeIPv6             |
|179                   |icmpCodeIPv6             |
|180                   |udpSourcePort            |
|181                   |udpDestinationPort       |
|182                   |tcpSourcePort            |
|183                   |tcpDestinationPort       |
|193                   |nextHeaderIPv6           |
|195                   |ipDiffServCodePoint      |
|196                   |ipPrecedence             |

## Configurable Informaiton Elements for Non-FlowKeys for collection
|Information Element ID|Information Element Name|
|----------------------|------------------------|
|1                     |octetDeltaCount         |
|2                     |packetDeltaCount        |
|6                     |tcpControlBits          |
|21                    |flowEndSysUpTime        |
|22                    |flowStartSysUpTime      |
|150                   |flowStartSeconds        |
|151                   |flowEndSeconds          |
|152                   |flowStartMilliseconds   |
|153                   |flowEndMilliseconds     |

## Functionality comparison with softflowd
|                        |softflowd              |goflowd  |
|------------------------|-----------------------|---------|
|Online packet capture   |supported              |supported|
|Reading pcap file       |supported(-r)          |supported|
|PSAMP collector         |supported(-R)          |TODO     |
|NetFlow version 1 export|supported(-v 1)        |TODO     |
|NetFlow version 5 export|supported(-v 5)        |supported|
|NetFlow version 7 export|unsupported            |TODO     |
|NetFlow version 8 export|unsupported            |TODO     |
|NetFlow version 9 export|supported(-v 9)        |TODO     |
|IPFIX export            |supported(-v 10)       |supported|
|IPv6 support(v9,IPFIX)  |supported(-6)          |supported|
|Bidirectioal flow export|supported(-b)          |TODO     |
|PSAMP export            |supported(-v PSAMP)    |TODO     |
|ntopng direct injection |supported(-v ntopng)   |TODO     |
|Flow export on UDP      |supported(-P udp)      |supported|
|Flow export on TCP      |supported(-P tcp)      |supported|
|Flow export on SCTP     |supported(-P sctp)     |TODO     |
|Configuration           |unsupported            |supported|
|FlowKey Configuration   |partially supported(-T)|supported|
|Count-based sampling    |supported              |supported|
|Time-based sampling     |unsupported            |supported|

## Limiation of IPFIX export in goflowd
- SCTP is mandatory in IPFIX ([RFC7011](https://tools.ietf.org/html/rfc7011)), however go's net.Dial does not support SCTP. Hence, goflowd does not support SCTP export.
- Every packets exported by goflowd contain Template Set.
- Option Template has not implemented.