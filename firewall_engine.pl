
:- include('rules_database.pl').



%% Adapter Clause %%
adapter(_,I) :- ((I ='any') -> true; false).									%% adapter any
adapter(AID,range(Min,Max)) :- 	(AID @>= Min, AID @=< Max) -> true ; false.		%% adapter A-C
adapter(AID,[H|T]) :- is_list(T), ((AID = H) -> true; adapter(AID,T)).			%% adapter A,D,E



%% Ethernet Clause %%
ether(_,vid(I)) :- ((I ='any') -> true; false). 																%% ether vid any
ether(_,proto(I)) :- ((I ='any') -> true; false). 																%% ether proto any

ether(PROTOCOL_ID,proto([H|T])) :- is_list(T), (((PROTOCOL_ID = H) -> true); ether(PROTOCOL_ID,proto(T))).		%% ether proto 0x0800, 0x86dd
ether(VID,vid([H|T])) :- is_list(T), (((VID = H) -> true); ether(VID,vid(T))).									%% ether vid 3,6

%% Range for VID
ether(VID,vid(range(Min,Max))) :- atom_number(VID,N_VID),
								  atom_number(Min,N_Min),
								  atom_number(Max,N_Max), 
								  ((N_VID >= N_Min, N_VID =< N_Max) -> true ; false).									%% ether vid 3-999

%% Combination of two
ether(VID,PROTOCOL_ID,VID_DATA,PROTO_DATA) :- ether(VID,VID_DATA), ether(PROTOCOL_ID,PROTO_DATA).				%% ether vid 3-999 proto 0x0800,0x86dd


bound([L_IP|T_IP],[L_Min|T_Min],[L_Max|T_Max]) :-  
			number_codes(MinIP,L_Min),
			 number_codes(MaxIP,L_Max),
			 number_codes(IP,L_IP),
			(IP >= MinIP, IP =< MaxIP),
			length(T_IP,Len), (Len = 0 -> true; bound(T_IP,T_Min,T_Max)).


%% IPv4 datagram clause %%
ip(_,src_addr(I)) :- ((I ='any') -> true; false).																%% ip src addr any
ip(_,dst_addr(I)) :- ((I ='any') -> true; false).																%% ip dst addr any
ip(_,proto(I)) :- ((I ='any') -> true; false).																	%% ip proto any

%% Range for SRC_IP
ip(SRC_IP,src_addr(range(Min,Max))) :- 
				split_string(Min,'.','',L_Min),
				split_string(Max,'.','',L_Max),
				split_string(SRC_IP,':','',L_IP),
				length(L_IP,IP_Format), IP_Format = 4,
				bound(L_IP,L_Min,L_Max).						%% ip src addr 192.168.10.0-192.168.10.255

%% Range for DST_IP
ip(DST_IP,dst_addr(range(Min,Max))) :-  
				split_string(Min,'.','',L_Min),
				split_string(Max,'.','',L_Max),
				split_string(DST_IP,':','',L_IP),
				length(L_IP,IP_Format), IP_Format = 4,
				bound(L_IP,L_Min,L_Max).

ip(SRC_IP,src_addr([H|T])) :- is_list(T), ((SRC_IP = H) -> true; ip(SRC_IP,src_addr(T))).						%% ip src addr 192.168.10.0,192.168.10.2
ip(DST_IP,dst_addr([H|T])) :- is_list(T), ((DST_IP = H) -> true; ip(DST_IP,dst_addr(T))).						%% ip dst addr 192.168.10.0,192.168.10.2
ip(PROTOCOL_TYPE,proto([H|T])) :- is_list(T), ((PROTOCOL_TYPE = H) -> true; ip(PROTOCOL_TYPE,proto(T))).		

%% Combination of two
ip(SRC_IP,DST_IP,SRC_DATA,DST_DATA) :- ip(SRC_IP,SRC_DATA), ip(DST_IP,DST_DATA).

%% Combination of three
ip(SRC_IP,DST_IP,PROTOCOL_TYPE,SRC_DATA,DST_DATA,PROTO_DATA) :- ip(SRC_IP,DST_IP,SRC_DATA,DST_DATA), ip(PROTOCOL_TYPE,PROTO_DATA).



%% IPv6 datagram clause %%
ipv6(_,src_addr(I)) :- ((I ='any') -> true; false).													%% ipv6 src addr any
ipv6(_,dst_addr(I)) :- ((I ='any') -> true; false).													%% ipv6 dst addr any
ipv6(_,proto(I)) :- ((I ='any') -> true; false).													%% ipv6 proto any



												

%% Range for SRC_IP
ipv6(SRC_IP,src_addr(range(Min,Max))) :- 
		split_string(Min,':','',L_Min),
		split_string(Max,':','',L_Max),
		split_string(SRC_IP,':','',L_IP),
		length(L_IP,IP_Format), IP_Format = 8,
		bound(L_IP,L_Min,L_Max).
															%% ipv6 src addr 101:0:0:0:0:0:0:101-101:0:0:0:0:0:0:200

%% Range for DST_IP
ipv6(DST_IP,src_addr(range(Min,Max))) :- 
		split_string(Min,':','',L_Min),
		split_string(Max,':','',L_Max),
		split_string(DST_IP,':','',L_IP),
		length(L_IP,IP_Format), IP_Format = 8,
		bound(L_IP,L_Min,L_Max).
															%% ipv6 dst addr 101:0:0:0:0:0:0:101-101:0:0:0:0:0:0:200

ipv6(SRC_IP,src_addr([H|T])) :- is_list(T), ((SRC_IP = H) -> true; ipv6(SRC_IP,src_addr(T))).
ipv6(DST_IP,dst_addr([H|T])) :- is_list(T), ((DST_IP = H) -> true; ipv6(DST_IP,dst_addr(T))).
ipv6(PROTOCOL_TYPE,proto([H|T])) :- is_list(T), ((PROTOCOL_TYPE = H) -> true; ipv6(PROTOCOL_TYPE,proto(T))).

%% Combination of two
ipv6(SRC_IP,DST_IP,SRC_DATA,DST_DATA) :- ipv6(SRC_IP,SRC_DATA), ipv6(DST_IP,DST_DATA).

%% Combination of three
ipv6(SRC_IP,DST_IP,PROTOCOL_TYPE,SRC_DATA,DST_DATA,PROTO_DATA) :- ipv6(SRC_IP,DST_IP,SRC_DATA,DST_DATA), ipv6(PROTOCOL_TYPE,PROTO_DATA).



%% TCP conditons %%
tcp(_,_,src_port(I)) :- ((I ='any') -> true; false).							%%tcp src port any
tcp(_,_,dst_port(I)) :- ((I ='any') -> true; false).							%%tcp dst port any

%% Range for SRC_PORT
tcp(PROTOCOL_TYPE,SRC_PORT,src_port(range(Min,Max))) :- PROTOCOL_TYPE = 'tcp', 
														atom_number(SRC_PORT,N_SRC_PORT),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_SRC_PORT >= N_Min, N_SRC_PORT =< N_Max) -> true ; false).

%% Range for DST_PORT
tcp(PROTOCOL_TYPE,DST_PORT,dst_port(range(Min,Max))) :- PROTOCOL_TYPE = 'tcp',
														atom_number(DST_PORT,N_DST_PORT),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_DST_PORT >= N_Min, N_DST_PORT =< N_Max) -> true ; false).

tcp(PROTOCOL_TYPE,SRC_PORT,src_port([H|T])) :- PROTOCOL_TYPE = 'tcp', is_list(T), ((SRC_PORT = H) -> true; tcp(PROTOCOL_TYPE,SRC_PORT,src_port(T))).
tcp(PROTOCOL_TYPE,DST_PORT,dst_port([H|T])) :- PROTOCOL_TYPE = 'tcp', is_list(T), ((DST_PORT = H) -> true; tcp(PROTOCOL_TYPE,DST_PORT,dst_port(T))).

%% Combination of two
tcp(PROTOCOL_TYPE,SRC_PORT,DST_PORT,SRC_DATA,DST_DATA) :- tcp(PROTOCOL_TYPE,SRC_PORT,SRC_DATA), tcp(PROTOCOL_TYPE,DST_PORT,DST_DATA).



%% udp conditons %%
udp(_,_,src_port(I)) :- ((I ='any') -> true; false).
udp(_,_,dst_port(I)) :- ((I ='any') -> true; false).

%% Range for SRC_PORT
udp(PROTOCOL_TYPE,SRC_PORT,src_port(range(Min,Max))) :- PROTOCOL_TYPE = 'udp', 
														atom_number(SRC_PORT,N_SRC_PORT),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_SRC_PORT >= N_Min, N_SRC_PORT =< N_Max) -> true ; false).

%% Range for DST_PORT
udp(PROTOCOL_TYPE,DST_PORT,dst_port(range(Min,Max))) :- PROTOCOL_TYPE = 'udp', 
														atom_number(DST_PORT,N_DST_PORT),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_DST_PORT >= N_Min, N_DST_PORT =< N_Max) -> true ; false).

udp(PROTOCOL_TYPE,SRC_PORT,src_port([H|T])) :- PROTOCOL_TYPE = 'udp', is_list(T), ((SRC_PORT = H) -> true; udp(PROTOCOL_TYPE,SRC_PORT,src_port(T))).
udp(PROTOCOL_TYPE,DST_PORT,dst_port([H|T])) :- PROTOCOL_TYPE = 'udp', is_list(T), ((DST_PORT = H) -> true; udp(PROTOCOL_TYPE,DST_PORT,dst_port(T))).

%% Combination of two
udp(PROTOCOL_TYPE,SRC_PORT,DST_PORT,SRC_DATA,DST_DATA) :- udp(PROTOCOL_TYPE,SRC_PORT,SRC_DATA), udp(PROTOCOL_TYPE,DST_PORT,DST_DATA).



%% ICMP conditons %% 
icmp(_,_,type(I)) :- ((I ='any') -> true; false).
icmp(_,_,code(I)) :- ((I ='any') -> true; false).

%% Range for ICMP_TYPE
icmp(PROTOCOL_TYPE,ICMP_TYPE,type(range(Min,Max))) :- PROTOCOL_TYPE = 'icmp', 
														atom_number(ICMP_TYPE,N_ICMP_TYPE),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_ICMP_TYPE >= N_Min, N_ICMP_TYPE =< N_Max) -> true ; false).

%% Range for ICMP_CODE
icmp(PROTOCOL_TYPE,ICMP_CODE,code(range(Min,Max))) :- PROTOCOL_TYPE = 'icmp', 
														atom_number(ICMP_CODE,N_ICMP_CODE),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_ICMP_CODE >= N_Min, N_ICMP_CODE =< N_Max) -> true ; false).

icmp(PROTOCOL_TYPE,ICMP_TYPE,type([H|T])) :- PROTOCOL_TYPE = 'icmp', is_list(T), ((ICMP_TYPE = H) -> true; icmp(PROTOCOL_TYPE,ICMP_TYPE,type(T))).
icmp(PROTOCOL_TYPE,ICMP_CODE,code([H|T])) :- PROTOCOL_TYPE = 'icmp', is_list(T), ((ICMP_CODE = H) -> true; icmp(PROTOCOL_TYPE,ICMP_CODE,code(T))).

%% Combination of two
icmp(PROTOCOL_TYPE,ICMP_TYPE,ICMP_CODE,ICMP_TYPE_DATA,ICMP_CODE_DATA) :- icmp(PROTOCOL_TYPE,ICMP_TYPE,ICMP_TYPE_DATA), icmp(PROTOCOL_TYPE,ICMP_CODE,ICMP_CODE_DATA).



%% ICMPv6 conditons %% 
icmpv6(_,_,type(I)) :- ((I ='any') -> true; false).
icmpv6(_,_,code(I)) :- ((I ='any') -> true; false).

%% Range for ICMP_TYPE
icmpv6(PROTOCOL_TYPE,ICMP_TYPE,type(range(Min,Max))) :- PROTOCOL_TYPE = 'icmpv6', 
														atom_number(ICMP_TYPE,N_ICMP_TYPE),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_ICMP_TYPE >= N_Min, N_ICMP_TYPE =< N_Max) -> true ; false).

%% Range for ICMP_CODE
icmpv6(PROTOCOL_TYPE,ICMP_CODE,code(range(Min,Max))) :- PROTOCOL_TYPE = 'icmpv6', 
														atom_number(ICMP_CODE,N_ICMP_CODE),
								  						atom_number(Min,N_Min),
								  						atom_number(Max,N_Max), 
														((N_ICMP_CODE >= N_Min, N_ICMP_CODE =< N_Max) -> true ; false).

icmpv6(PROTOCOL_TYPE,ICMP_TYPE,type([H|T])) :- PROTOCOL_TYPE = 'icmpv6', is_list(T), ((ICMP_TYPE = H) -> true; icmpv6(PROTOCOL_TYPE,ICMP_TYPE,type(T))).
icmpv6(PROTOCOL_TYPE,ICMP_CODE,code([H|T])) :- PROTOCOL_TYPE = 'icmpv6', is_list(T), ((ICMP_CODE = H) -> true; icmpv6(PROTOCOL_TYPE,ICMP_CODE,code(T))).

%% Combination of two
icmpv6(PROTOCOL_TYPE,ICMP_TYPE,ICMP_CODE,ICMP_TYPE_DATA,ICMP_CODE_DATA) :- icmpv6(PROTOCOL_TYPE,ICMP_TYPE,ICMP_TYPE_DATA), icmpv6(PROTOCOL_TYPE,ICMP_CODE,ICMP_CODE_DATA).


%% Only packet is called while querying


packet(
	AID,
	eth(VID,PROTOCOL_ID),
	ip_info(SRC_IP,DST_IP,PROTOCOL_TYPE)
	) 
	:- rules(State,AID,SRC_IP,DST_IP,PROTOCOL_ID,PROTOCOL_TYPE,VID,null,null,null,null), atom_concat('Firewall Decision: ',State,Stmt), write(Stmt).

packet(
	AID,
	eth(VID,PROTOCOL_ID),
	ip_info(SRC_IP,DST_IP,PROTOCOL_TYPE),
	tcp_udp(SRC_PORT,DST_PORT)
	) 
	:- rules(State,AID,SRC_IP,DST_IP,PROTOCOL_ID,PROTOCOL_TYPE,VID,SRC_PORT,DST_PORT,null,null), atom_concat('Firewall Decision: ',State,Stmt), write(Stmt).

packet(
	AID,
	eth(VID,PROTOCOL_ID),
	ip_info(SRC_IP,DST_IP,PROTOCOL_TYPE),
	icmp(ICMP_TYPE,ICMP_CODE)
	) 
	:- rules(State,AID,SRC_IP,DST_IP,PROTOCOL_ID,PROTOCOL_TYPE,VID,null,null,ICMP_TYPE,ICMP_CODE), atom_concat('Firewall Decision: ',State,Stmt), write(Stmt).

packet(
	AID,
	eth(VID,PROTOCOL_ID),
	ip_info(SRC_IP,DST_IP,PROTOCOL_TYPE),
	icmpv6(ICMP_TYPE,ICMP_CODE)
	) 
	:- rules(State,AID,SRC_IP,DST_IP,PROTOCOL_ID,PROTOCOL_TYPE,VID,null,null,ICMP_TYPE,ICMP_CODE), atom_concat('Firewall Decision: ',State,Stmt), write(Stmt).
