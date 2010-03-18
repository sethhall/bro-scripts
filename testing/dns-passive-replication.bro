@load global-ext
@load dns

# Modify the DNS analyzer to give us Authority and Additional section responses.
redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
	# If set to T, this will split the log into separate files.
	# F merges everything into a single file.
	const split_log_file = F &redef;
	
	# Which DNS servers replies should be logged.
	# Choices are: LocalHosts, RemoteHosts, AllHosts, NoHosts
	const logging_replies = AllHosts &redef;
}

# Turn off the dns.log file.
redef logging = F;

event bro_init()
	{
	LOG::create_logs("dns-passive-replication", logging_replies, split_log_file, T);
	
	LOG::define_header("dns-passive-replication",
	                   cat_sep("\t", "\\N", 
	                           "ts",
	                           "orig_h", "orig_p", "resp_h", "resp_p",
	                           "proto", "query",
	                           "AA", "TTL", "query_class", "query_type",
	                           "annotation", "response"));
	}

const dns_response_sections: table[count] of string = {
	[0] = "QUERY",
	[1] = "ANS",
	[2] = "AUTH",
	[3] = "ADDL",
};

function print_DNS_RR(c: connection, msg: dns_msg, ans: dns_answer, anno: string)
	{
	local log = LOG::get_file_by_addr("dns-passive-replication", c$id$resp_h, F);
	print log, cat_sep("\t", "\\N",
	                   network_time(),
	                   c$id$orig_h, port_to_count(c$id$orig_p),
	                   c$id$resp_h, port_to_count(c$id$resp_p),
	                   get_port_transport_proto(c$id$resp_p),
	                   ans$query,
	                   msg$AA,
	                   fmt("%.0f", interval_to_double(ans$TTL)),
	                   dns_class[ans$qclass],
	                   query_types[ans$qtype],
	                   anno, 
	                   dns_response_sections[ans$answer_type]);
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	print_DNS_RR(c, msg, ans, fmt("%s", a));
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string)
	{
	print_DNS_RR(c, msg, ans, str);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string)
	{
	# TODO: not sure what's in astr
	print_DNS_RR(c, msg, ans, fmt("%s", a));
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count)
	{
	# TODO: maybe deal with preference?
	print_DNS_RR(c, msg, ans, name);
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print_DNS_RR(c, msg, ans, name);
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print_DNS_RR(c, msg, ans, name);
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	print_DNS_RR(c, msg, ans, name);
	}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	# need to make a function to log this...
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	print_DNS_RR(c, msg, ans, soa$mname);
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	# need to make a function to log this...
	}

event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	# need to make a function to log this...
	}
