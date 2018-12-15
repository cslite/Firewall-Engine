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

2. `rules_database.pl` initially contains some sample rules. These rules can be changed and new rules can be added (For Syntax, Refer [Rules Format](/#rules-format)). 

3. Refer [Packet Format](/#packet-format) to know, how to pass valid packets to the engine. These are queries. 

4. Based on an input network packet and the rules mentioned in the `rules_database.pl`, a single string is the output(viz. reject, accept, drop).

