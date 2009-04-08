@load global-ext
@load dns

module DNS;

export {
	const local_domains = /(^|\.)(osu|ohio-state)\.edu$/ | 
	                      /(^|\.)akamai(tech)?\.net$/ &redef;
	
	const dns_ext_log = open_log_file("dns-ext") &raw_output;
	
	redef enum Notice += { 
		# Raised when a non-local name is found to be pointing at a local host.
		#  This only works appropriately when all of your authoritative DNS 
		#  servers are located in your "local_nets".
		DNSExternalName, 
		};
}

type dns_session_info_ext: record {
	id: conn_id;
	start: time;
	query: string;
	qtype: count;
	qclass: count;
	total_answers: count &default=0;
	rcode: count &default = 65536;
	QR: bool &default=F;
	Z:  bool &default=F;
	AA: bool &default=F;
	RD: bool &default=F;
	RA: bool &default=F;
	TC: bool &default=F;
	TTL: interval &default=0secs;
	replies: set[string];
};

global dns_sessions_ext: table[addr, addr, count] of dns_session_info_ext;


# This doesn't work with live traffic yet.
# It's waiting for support to dynamically construct pattern variables at runtime.
#global dns_suffix_regex = build_regex(local_domains, "(^|\.)~~$");
#event bro_init()
#	{
#	local i: count = 0;
#	local tmp_pattern: pattern;
#	for ( d in local_domains )
#		{
#		tmp_pattern = string_to_pattern( fmt("=%s@", d), T );
#		
#		if ( i == 0 )
#			pat = tmp_pattern;
#		else
#			pat = merge_pattern(tmp_pattern, pat);
#		++i;
#		}
#	}

event expire_DNS_session_ext(orig: addr, resp: addr, trans_id: count)
	{
	if ( [orig, resp, trans_id] in dns_sessions_ext )
		{
		local session = dns_sessions[orig, resp, trans_id];
		local session_ext = dns_sessions_ext[orig, resp, trans_id];
		
		local flags: set[string];
		if ( session_ext$RD )
			add flags["RD"];
		if ( session_ext$RA )
			add flags["RA"];
		if ( session_ext$TC )
			add flags["TC"];
		if ( session_ext$QR )
			add flags["QR"];
		if ( session_ext$Z )
			add flags["Z"];
		if ( session_ext$AA )
			add flags["AA"];
		
		print dns_ext_log, cat_sep("\t", "\\N",
		                           session_ext$start,
		                           session$last_active,
		                           orig, fmt("%s",session_ext$id$orig_p),
		                           resp, fmt("%s",session_ext$id$resp_p),
		                           query_types[session_ext$qtype],
		                           dns_class[session_ext$qclass],
		                           session_ext$query, fmt("%04x",trans_id),
		                           fmt("%.0f", interval_to_double(session_ext$TTL)),
		                           fmt_str_set(flags, /!!!!/),
		                           base_error[session_ext$rcode],
		                           fmt_str_set(session_ext$replies, /!!!!/)
		                           );
		
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	if ( [orig, resp, msg$id] !in dns_sessions_ext )
		{
		session_ext$id = c$id;
		session_ext$start = network_time();
		session_ext$RD = msg$RD;
		session_ext$TC = msg$TC;
		session_ext$qtype = qtype;
		session_ext$qclass = qclass;
		session_ext$query = query;
		local strings: set[string] = set();
		session_ext$replies = strings;
		dns_sessions_ext[orig, resp, msg$id] = session_ext;
		
		# This needs to expire before the original dns.bro script expires the 
		# the data from the dns_session variable.
		schedule 14secs { expire_DNS_session_ext(orig, resp, msg$id) };
		}
	}


event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		add session_ext$replies[fmt("%s",a)];
		session_ext$RA = msg$RA;
		session_ext$TTL = ans$TTL;
		session_ext$rcode = msg$rcode;
		}
	
	
	# Check for out of place domain names
	if ( is_local_addr(a) &&            # referring to a local host
	     !is_local_addr(c$id$resp_h) && # response from a remote host
	     local_domains !in ans$query )  # drop known names
		{
		NOTICE([$note=DNSExternalName,
		        $msg=fmt("%s is pointing to a local host - %s.", ans$query, a),
		        $conn=c]);
		}
	}
	
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[str];
		}
	}
	
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[fmt("%s", a)];
		}
	}


event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[name];
		}
	}
	
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[name];
		}
	}
	
#event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
#	{
#	print query;
#	}

event dns_end(c: connection, msg: dns_msg)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_session_info_ext;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		}	
	}
	
	
event bro_done()
	{
	print dns_sessions_ext;
	}