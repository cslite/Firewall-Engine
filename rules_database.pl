rules(State,AID,SRC_IP,DST_IP,PROTOCOL_ID,PROTOCOL_TYPE,VID,SRC_PORT,DST_PORT,ICMP_TYPE,ICMP_CODE) :- /* DO NOT MODIFY */
		/*WRITE YOUR RULES BELOW THIS LINE IN THE ORDER OF PRECEDENCE.*/
		

		/* WRITE YOUR RULES HERE (or below rules are given for sample run). */


		State = reject, adapter(AID,['A']), ip(PROTOCOL_TYPE,proto(['tcp']));
		State = accept, adapter(AID,['G','B']), ether(PROTOCOL_ID,proto(['0x0800']));
		State = accept, adapter(AID,['I','K']),ether(VID,PROTOCOL_ID,vid(['3']),proto(['0x0800']));
		State = accept, ip(DST_IP,dst_addr(['192.168.0.1','172.17.56.41'])), tcp(PROTOCOL_TYPE,DST_PORT,dst_port(['80']));
		State = accept, adapter(AID,['L']),ip(SRC_IP,src_addr(['192.168.1.1'])),udp(PROTOCOL_TYPE,DST_PORT,dst_port(['80','23']));
		State = drop, 	adapter(AID,['J']),ipv6(SRC_IP,src_addr(['101:0:0:0:0:0:0:101']));
		State = drop,	ether(VID,vid(range('3','9'))),icmp(PROTOCOL_TYPE,ICMP_TYPE,type(['2','3']));
		State = reject, udp(PROTOCOL_TYPE,SRC_PORT,src_port(range('20','80')));
		State = accept,	icmpv6(PROTOCOL_TYPE,ICMP_CODE,code('4'));



		/* DO NOT WRITE BELOW THIS LINE. */
		State = reject. /* DO NOT MODIFY. This is the default rule. This incorporates the fact that 'Everything is rejected by default'. */
