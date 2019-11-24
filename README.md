# goflowd

## Sumarry
goflowd is netflow probe like [softflowd](https://github.com/irino/softflowd).
It is written by golang.  goflowd uses
[ietf-ipfix-psamp.yang](https://github.com/YangModels/yang/blob/master/standard/ietf/RFC/ietf-ipfix-psamp%402012-09-05.yang)
standarized in [RFC6728](https://tools.ietf.org/html/rfc6728) data
model for configuration. The yang model configuraiton is acheived by using [openconfig/ygot](https://github.com/openconfig/ygot).

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

## Configurable Informaiton Elements
|Information Element ID|Information Element Name |
|----------------------|-------------------------|
|4                     |protocolIdentifier       |
|5                     |ipClassOfService         |
|6                     |tcpControlBits           |
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