# Firewall Engine
Prolog implementation of the Firewall Rule Language. Firewall Rules are encoded in prolog as facts and rules. This firewall engine decides whether a given packet should be accepted, rejected or dropped based on the saved firewall rules.

## How to Use
You need a Prolog Environment installed ([SWI-Prolog](http://www.swi-prolog.org/) is preferred) to run this program.

### Important Points to be Noted
1. All inputs in the packet are strings(use single quotes viz. 'your-input-here').
2. Enter IPv6 address as the decimal equivalent of the original IPv6 Address. (Decimal Equivalent of an IPv6 address means decimal equivalent of each of its component). For example, 

   Decimal Equivalent of `FF01:0:0:0:0:0:0:AB01` is `65281:0:0:0:0:0:0:43777`

3. The engine is priority based i.e. the rules are tested for truth and the very first rule that can be satisfied decides the fate of the packet(viz. reject, drop, accept).
4. The rule at the bottommost level is reject-all i.e. a packet will be accepted if and only if it satisfies one of the user   
   mentioned accept rule. DO NOT ALTER THIS BOTTOMMOST REJECT-ALL RULE.
5. It is assumed that the user enters a valid packet. Validity of packets is not checked.

### Files
- `firewall_engine.pl`  
This is the engine which applies the rules mentioned by the user. DO NOT CHANGE ANYTHING IN THIS FILE.
- `rules_database.pl`   
This file contains the rules to be consulted while deciding fate of the packet.

### Steps to Use
1. In SWI-Prolog, consult only the `firewall_engine.pl` file. It internally uses `rules_database.pl` which you CAN MODIFY as 
   per requirement.

2. `rules_database.pl` initially contains some sample rules. These rules can be changed and new rules can be added (For Syntax, Refer [Rules Format](/README.md#rules-format)). 

3. Refer [Packet Format](/README.md#packet-format) to know, how to pass valid packets to the engine. These are queries. 

4. Based on an input network packet and the rules mentioned in the `rules_database.pl`, a single string is the output(viz. reject, accept, drop).

## Packet Format

| Packet Type | WHEN TO USE |
| --- | --- |
| 1 | protocol-type is none of `'tcp', 'udp', 'icmp', 'icmpv6'` |
| 2 | protocol-type is `'tcp' or 'udp'` |
| 3 | protocol-type is `'icmp'` |
| 4 | protocol-type is `'icmpv6'` |

- **TYPE 1** *(adapter-id, ethernet(VLAN-id, protocol_id), ip_information(source-address, desination-address, protocol-type))*

   **SYNTAX:** `packet(ADAPTER_ID,eth(VLAN_ID,PROTOCOL_ID),ip_info(SOURCE_IP,DESTINATION_IP,PROTOCOL_TYPE)).`
   
   For example,
	```prolog
      packet('B', eth('5','0x0800'), ip_info('192.168.0.1','192.168.2.1','xns')).
   ```
- **TYPE 2** *(adapter-id, ethernet(VLAN-id, protocol_id), ip_information(source-address, desination-address, protocol-type = 'tcp|udp'), tcp_or_udp_information(source-port, destination-port))*

   **SYNTAX:** `packet(ADAPTER_ID,eth(VLAN_ID,PROTOCOL_ID),ip_info(SOURCE_IP,DESTINATION_IP,PROTOCOL_TYPE),tcp_udp(SORCE_PORT,DESTINATION_PORT)).` 
   
   For example,
   ```prolog
	   packet('C', eth('45','0x86dd'), ip_info('192.168.43.5','192.168.137.1','tcp'), tcp_udp('80','23')).
   ```
- **TYPE 3** *(adapter-id, ethernet(VLAN-id, protocol_id), ip_information(source-address, desination-address, protocol-type = 'icmp'), icmp_information(icmp-protocol-type, icmp-message-code))*

   **SYNTAX:** `packet(ADAPTER_ID,eth(VLAN_ID,PROTOCOL_ID),ip_info(SOURCE_IP,DESTINATION_IP,PROTOCOL_TYPE),icmp(ICMP_TYPE,ICMP_CODE)).` 

   For example,
   ```prolog
	   packet('F', eth('17','0x86dd'), ip_info('192.168.4.5','192.168.17.1','icmp'), icmp('23','9')).
   ```
   
- **TYPE 4** *(adapter-id, ethernet(VLAN-id, protocol_id), ip_information(source-address, desination-address, protocol-type = 'icmpv6'), icmpv6_information(icmpv6-protocol-type, icmpv6-message-code))*

   **SYNTAX:** `packet(ADAPTER_ID,eth(VLAN_ID,PROTOCOL_ID),ip_info(SOURCE_IP,DESTINATION_IP,PROTOCOL_TYPE),icmpv6(ICMP_TYPE,ICMP_CODE)).` 

   For example,
   ```prolog
	   packet('G', eth('49','0x0800'), ip_info('101:0:0:0:0:0:0:101','101:0:0:0:0:0:0:200','icmpv6'), icmpv6('33','239')).
   ```
 
 ## Rules Format
 
 **NOTE:** PLEASE DONOT MODIFY THE ARGUMENTS WRITTEN IN UPPERCASE CHARACTERS IN EACH OF THE CLAUSE, those variables are required to pass values to the predicates.

_Each rule must end with a semi-colon (;). Only the last rule which is the default rule ends with a Full-Stop (.)_

These rules are based on the **Firewall Rule Language**, given [here](https://www.ibm.com/support/knowledgecenter/en/SSB2MG_4.6.0/com.ibm.ips.doc/concepts/firewall_rules_language.htm).

### Firewall Clauses (Examples of valid Clauses)
You can make a rule consisting of a single clause, or multiple clauses chained together.

#### 1. Adapter Clause

```prolog
	State = accept, adapter(AID,'any');

	State = accept, adapter(AID,['A']);
	State = reject, adapter(AID,['A','C','D']);
	
	State = drop, 	adapter(AID,range('B','E'));
```

#### 2. Ethernet Clause

```prolog
	State = accept, ether(PROTOCOL_ID,proto('any'));
	State = accept, ether(VID,vid('any'));
	
	State = reject, ether(PROTOCOL_ID,proto(['0x0800']));
	State = reject, ether(VID,vid(['3']));
	
	State = drop, 	ether(VID,vid(range('3','9')));
	State = drop, 	ether(VID,PROTOCOL_ID,vid(range('3','9')),proto(['0x0800']));
```

#### 3. IPv4 datagram clause

```prolog
	State = drop, 		ip(SRC_IP,src_addr('any'));
	State = accept, 	ip(DST_IP,dst_addr('any'));
	State = reject, 	ip(PROTOCOL_TYPE,proto('any'));

	State = reject, 	ip(SRC_IP,src_addr(['192.168.1.1']));
	State = reject, 	ip(DST_IP,dst_addr(['192.168.0.1','172.17.56.41']));

	State = reject, 	ip(DST_IP,dst_addr(range('192.168.1.1','192.168.1.100'));
	
	State = accept, 	ip(SRC_IP,DST_IP,src_addr(['192.168.1.1']),dst_addr(['192.168.0.1','172.17.56.41']));
	State = drop, 		ip(SRC_IP,DST_IP,PROTOCOL_TYPE,src_addr(['192.168.1.1']),dst_addr(['192.168.0.1']),proto(['tcp']));
```

#### 4. IPv6 datagram clause
```prolog
	State = drop, 		ipv6(SRC_IP,src_addr('any'));
	State = accept, 	ipv6(DST_IP,dst_addr('any'));
	State = reject, 	ipv6(PROTOCOL_TYPE,proto('any'));

	State = reject, 	ipv6(SRC_IP,src_addr(['101:0:0:0:0:0:0:101']));
	State = reject, 	ipv6(DST_IP,dst_addr(['101:0:0:0:0:0:0:101','101:0:0:0:0:0:0:200']));

	State = accept, 	ipv6(SRC_IP,DST_IP,src_addr(['101:0:0:0:0:0:0:200']),dst_addr(['101:0:0:0:0:0:0:101','101:0:0:0:0:0:0:105']));
	State = drop, 		ipv6(SRC_IP,DST_IP,PROTOCOL_TYPE,src_addr(['101:0:0:0:0:0:0:200']),dst_addr(['101:0:0:0:0:0:0:101']),proto(['icmp']));
```
### Firewall Condtions

#### 1. TCP & UDP Conditions

**Note that**, `PROTOCOL_TYPE` in the ip field of the Packet must be `'tcp'` or `'udp'` for respective rule to be effective.
```prolog
	State = drop, 		tcp(PROTOCOL_TYPE,SRC_PORT,src_port('any'));
	State = accept, 	tcp(PROTOCOL_TYPE,DST_PORT,dst_port('any'));

	State = reject, 	tcp(PROTOCOL_TYPE,SRC_PORT,src_port(['80','23']));
	State = reject, 	tcp(PROTOCOL_TYPE,DST_PORT,dst_port(['80']));

	State = reject, 	tcp(PROTOCOL_TYPE,SRC_PORT,src_port(range('20','80')));
	State = accept, 	tcp(PROTOCOL_TYPE,DST_PORT,dst_port(range('20','60')));

	State = drop, 		tcp(PROTOCOL_TYPE,SRC_PORT,DST_PORT,src_port(range('20','80')),dst_port(['80']));

	State = drop, 		udp(PROTOCOL_TYPE,SRC_PORT,src_port('any'));
	State = accept, 	udp(PROTOCOL_TYPE,DST_PORT,dst_port('any'));
	State = reject, 	udp(PROTOCOL_TYPE,SRC_PORT,src_port(['80','23']));
	State = reject, 	udp(PROTOCOL_TYPE,DST_PORT,dst_port(['80']));
	State = reject, 	udp(PROTOCOL_TYPE,SRC_PORT,src_port(range('20','80')));
	State = accept, 	udp(PROTOCOL_TYPE,DST_PORT,dst_port(range('20','60')));
	State = drop, 		udp(PROTOCOL_TYPE,SRC_PORT,DST_PORT,src_port(range('20','80')),dst_port(['80']));
```

#### 2. ICMP Conditions

**Note that**, `PROTOCOL_TYPE` in the ip field of the Packet must be `'icmp'` for rule to be effective.
```prolog
	State = accept,		icmp(PROTOCOL_TYPE,ICMP_TYPE,type('any'));
	State = accept,		icmp(PROTOCOL_TYPE,ICMP_CODE,code('any'));
	
	State = reject,		icmp(PROTOCOL_TYPE,ICMP_TYPE,type(['2','3']));
	State = reject,		icmp(PROTOCOL_TYPE,ICMP_CODE,code(['7','9']));
	
	State = drop, 		icmp(PROTOCOL_TYPE,ICMP_TYPE,ICMP_CODE,type(['2','3']),code(range('5','9')));
```

#### 3. ICMPv6 Condtions

**Note that**, `PROTOCOL_TYPE` in the ip field of the Packet must be `'icmpv6'` for rule to be effective.
```prolog
	State = accept,		icmpv6(PROTOCOL_TYPE,ICMP_TYPE,type('any'));
	State = accept,		icmpv6(PROTOCOL_TYPE,ICMP_CODE,code('any'));

	State = reject,		icmpv6(PROTOCOL_TYPE,ICMP_TYPE,type(['2','3']));
	State = reject,		icmpv6(PROTOCOL_TYPE,ICMP_CODE,code(['7','9']));

	State = drop, 		icmpv6(PROTOCOL_TYPE,ICMP_TYPE,ICMP_CODE,type(['2','3']),code(range('5','9')));
```

### Complex Rules made by chaining of Clauses & Packet Examples

#### RULE - 1
```prolog	
State = reject, adapter(AID,['A']), ip(PROTOCOL_TYPE,proto(['tcp']));
```
EXAMPLE PACKET THAT GETS REJECTED BY THIS RULE-
```prolog
packet('A',eth('1','0x0800'),ip_info('0.0.0.0','192.168.1.1','tcp')).
```

#### RULE - 2
```prolog
State = reject, adapter(AID,['G','B']), ether(PROTOCOL_ID,proto(['0x0800']));
```
EXAMPLE PACKET THAT GETS REJECTED BY THIS RULE-
```prolog
packet('B',eth('7','0x0800'),ip_info('0.0.0.0','192.168.1.1','xnet')).
```

#### RULE - 3
```prolog
State = accept, adapter(AID,['I','K']),ether(VID,PROTOCOL_ID,vid(['3']),proto(['0x0800']));
```
EXAMPLE PACKET THAT GETS ACCEPTED BY THIS RULE-
```prolog
packet('I',eth('3','0x0800'),ip_info('0.0.0.0','192.168.1.1','igmp')).
```

#### RULE - 4
```prolog
State = accept, ip(DST_IP,dst_addr(['192.168.0.1','172.17.56.41'])), tcp(PROTOCOL_TYPE,DST_PORT,dst_port(['80']));
```
EXAMPLE PACKET THAT GETS ACCEPTED BY THIS RULE-
```prolog
packet('H',eth('1','0x08dd'),ip_info('192.168.1.1','172.17.56.41','tcp'),tcp_udp('23','80')).
```

#### RULE - 5
```prolog
State = accept, adapter(AID,['L']),ip(SRC_IP,src_addr(['192.168.1.1'])),udp(PROTOCOL_TYPE,DST_PORT,dst_port(['80','23']));
```
EXAMPLE PACKET THAT GETS ACCEPTED BY THIS RULE-
```prolog
packet('L',eth('2','0x08dd'),ip_info('192.168.1.1','172.17.56.41','udp'),tcp_udp('55','23')).
```

#### RULE - 6
```prolog
State = drop, adapter(AID,['J']),ipv6(SRC_IP,src_addr(['101:0:0:0:0:0:0:101']));
```
EXAMPLE PACKET THAT GETS DROPPED BY THIS RULE-
```prolog
packet('J',eth('8','0x0800'),ip_info('101:0:0:0:0:0:0:101','101:0:0:0:0:0:0:200','tcp'),tcp_udp('55','23')).
```

#### RULE - 7
```prolog
State = drop, ether(VID,vid(range('3','9'))),icmp(PROTOCOL_TYPE,ICMP_TYPE,type(['2','3']));
```
EXAMPLE PACKET THAT GETS DROPPED BY THIS RULE-
```prolog
packet('E',eth('6','0x08dd'),ip_info('192.168.1.1','172.17.56.41','icmp'),icmp('3','0')).
```

#### RULE - 8
```prolog
State = drop, ether(VID,vid(range('13','20'))),icmpv6(PROTOCOL_TYPE,ICMP_TYPE,code(['2','3']));
```
EXAMPLE PACKET THAT GETS DROPPED BY THIS RULE-
```prolog
packet('F',eth('15','0x08dd'),ip_info('101:0:0:0:0:0:0:101','101:0:0:0:0:0:0:200','icmpv6'),icmpv6('6','2')).
```
