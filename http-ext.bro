@load global-ext
@load http-request

# I'm working to remove the dependency on this, but I'm not there yet.
@load http-reply

module HTTP;

# Comment out the next line if you don't have or don't want the malware.com.br
# dataset included.
#@load malware_com_br_block_list-data

export {
	# Open the log files
	global http_ext_log = open_log_file("http-ext") &raw_output &redef;
	global http_malware_log = open_log_file("http-malware") &raw_output &redef;
	global http_ua_log = open_log_file("http-user-agents") &raw_output &redef;
	global http_sql_injections_log = open_log_file("http-sql-injections") &raw_output &redef;

	redef enum Notice += { 
		HTTP_Suspicious,
		HTTP_Malware_com_br_Block_List,
		HTTP_SQL_Injection_Attempt,
		HTTP_SQL_Injection_Heavy_Probing,
	};
	
	# Which webservers to log requests for.
	#   Note that if you choose All or Remote, it will indiscriminately log 
	#   your user's host HTTP requests.
	# Choices are: LocalHosts, RemoteHosts, AllHosts
	const log_requests_toward: Hosts = AllHosts &redef;
	
	# This is list of subnets containing web servers that you'd like to log their
	# traffic regardless of the "log_requests_toward" variable.
	const ok_to_log: set[subnet] &redef;
	
	# Which hosts we care about logging user-agents.
	# You probably want to leave this alone becase of high memory use.
	# Choices are: LocalHosts, RemoteHosts, AllHosts
	const log_user_agents_of: Hosts = LocalHosts &redef;
	
	# This is the regular expression that is used to match URL based SQL injections
	const sql_injection_regex = 
		  /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])[^a-zA-Z&]/
		| /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([oO][rR]|[aA][nN][dD])([[:blank:]]|\/\*.*?\*\/)+['"]?[^a-zA-Z&]+?=/
		| /[\?&][^[:blank:]]+?=[\-0-9%]*([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/)*(\-|\+|\|\|)([[:blank:]]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\|]+?=([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/|;)*([oO][rR]|[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT]|\()[^a-zA-Z&]/
		| /[\?&][^[:blank:]]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/;

	# SQL injection probes are considered to be:
	#  1. A single single-quote at the end of a URL with no other single-quotes.
	#  2. URLs with one single quote at the end of a normal GET value.
	const sql_injection_probe_regex = 
		  /^[^\']+\'$/ 
		| /^[^\']+\'&[^\']*$/;
	const sql_injection_probe_threshold = 5;
	
	# HTTP post data contents that appear suspicious.
	#  This is usually spamming forum postings and the like.
	const suspicious_http_posts = 
		/[vV][iI][aA][gG][rR][aA]/ | 
		/[tT][rR][aA][mM][aA][dD][oO][lL]/ |
		/[cC][iI][aA][lL][iI][sS]/ | 
		/[sS][oO][mM][aA]/ | 
		/[hH][yY][dD][rR][oO][cC][oO][dD][oO][nN][eE]/ |
		/[cC][aA][nN][aA][dD][iI][aA][nN].{0,15}[pP][hH][aA][rR][mM][aA][cC][yY]/ |
		/[rR][iI][nN][gG].?[tT][oO][nN][eE]/ |
		/[pP][eE][nN][iI][sS]/ | 
		/[oO][nN][lL][iI][nN][eE].?[cC][aA][sS][iI][nN][oO]/ |
		/[rR][eE][mM][oO][rR][tT][gG][aA][gG][eE][sS]/ |
		# more than 4 bbcode style links in a POST is deemed suspicious
		/(url=http:.*){4}/ | 
		# more that 4 html links is also suspicious
		/(a.href(=|%3[dD]).*){4}/ &redef;
}

global sql_injection_probes_from: table[addr] of count &default=0 &create_expire=10mins &synchronized;

type http_info: record {
	host: string &default="";
	referer: string &default="";
	user_agent: string &default="";
	proxied_for: string &default="";
};

global http_log_post: set[conn_id] &write_expire=15secs;

function default_http_session_info(id: conn_id): http_info
	{
	local tmp: http_info;
	return tmp;
	}

global session_http_info: table[conn_id] of http_info &default=default_http_session_info &write_expire=15secs;

# remember the set of user agents at an ip address for while
global http_remember_user_agents: table[addr] of string_set &synchronized &create_expire=1hr;

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=5
	{
	if ( !is_orig )
		return; 
	
	local id = c$id;
	local s = lookup_http_request_stream(c);
	if ( s$first_pending_request !in s$requests )
		return;
	
	local msg = get_http_message(s, is_orig);
	local r = s$requests[s$first_pending_request];
	local host = session_http_info[c$id]$host;
	local url = fmt("http://%s%s", host, r$URI);
	
	if ( resp_matches_hosts(id$resp_h, log_requests_toward) || 
	     id$resp_h in ok_to_log )
	
		print http_ext_log, cat_sep("\t", "\\N", network_time(), 
		                                         id$orig_h, 
		                                         fmt("%d", id$orig_p), 
		                                         id$resp_h, 
		                                         fmt("%d", id$resp_p),
		                                         r$method, 
		                                         url, 
		                                         session_http_info[c$id]$referer);
	
	local log_sql=F;
	local direction = "";
	# Detect and log SQL injection attempts in their own log file
	if ( sql_injection_regex in r$URI )
		{
		log_sql=T;
		direction = "outbound";
		if ( is_local_addr(id$resp_h) )
			direction="inbound";
		}
	if ( sql_injection_probe_regex in r$URI )
		{
		log_sql=T;
		direction="PROBE";
		if ( ++sql_injection_probes_from[id$orig_h] >= sql_injection_probe_threshold )
			NOTICE([$note=HTTP_SQL_Injection_Heavy_Probing, 
			        $msg=fmt("Heavy probing from %s", id$orig_h), 
			        $n=sql_injection_probes_from[id$orig_h], 
			        $conn=c]);
		}
	if ( log_sql )
		{
		print http_sql_injections_log, cat_sep("\t", "\\N", network_time(), 
		                                 id$orig_h, fmt("%d", id$orig_p), 
		                                 id$resp_h, fmt("%d", id$resp_p), 
		                                 direction, r$method, url, 
		                                 session_http_info[c$id]$referer, 
		                                 session_http_info[c$id]$user_agent, 
		                                 session_http_info[c$id]$proxied_for);
		NOTICE([$note=HTTP_SQL_Injection_Attempt,
		        $msg=fmt("SQL Injection request: %s -> %s", 
		                 numeric_id_string(id), url),
		        $conn=c]);
		}
	
@ifdef ( MalwareComBr_BlockList )
	if ( MalwareComBr_BlockList in url )
		{
		add http_log_post[id];
		local malware_com_br_msg = fmt("%s %s %s", r$method, url, referrer);
		NOTICE([$note=HTTP_Malware_com_br_Block_List, $msg=malware_com_br_msg, $conn=c]);
		}
@endif
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( is_orig && 
	     (c$id in http_log_post || suspicious_http_posts in data) )
		{
		print http_ext_log, fmt("%.6f %s POST data: %s User-Agent: %s Referrer: %s Proxied for: %s", 
		                        network_time(), numeric_id_string(c$id), data, 
		                        session_http_info[c$id]$user_agent, 
		                        session_http_info[c$id]$referer, 
		                        session_http_info[c$id]$proxied_for);
		}
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( !is_orig ) return;

	if ( c$id !in session_http_info )
		{
		local blah: http_info;
		session_http_info[c$id] = blah;
		}

	if ( name == "REFERER" )
		session_http_info[c$id]$referer = value; 

	if ( name == "USER-AGENT" )
		{
		session_http_info[c$id]$user_agent = value;
		if ( resp_matches_hosts(c$id$orig_h, log_user_agents_of) &&
		    (c$id$orig_h !in http_remember_user_agents ||
		     (c$id$orig_h in http_remember_user_agents && 
		      value !in http_remember_user_agents[c$id$orig_h]) ) )
			{
			if ( c$id$orig_h !in http_remember_user_agents )
				http_remember_user_agents[c$id$orig_h] = set();
			add http_remember_user_agents[c$id$orig_h][value];
			print http_ua_log, fmt("%.6f %s %s", network_time(), c$id$orig_h, value);
			}
		}

	if ( name == "HTTP_FORWARDED" ||
	     name == "FORWARDED" ||
	     name == "HTTP_X_FORWARDED_FOR" ||
	     name == "X_FORWARDED_FOR" ||
	     name == "HTTP_X_FORWARDED_FROM" ||
	     name == "X_FORWARDED_FROM" ||
	     name == "HTTP_CLIENT_IP" ||
	     name == "CLIENT_IP" ||
	     name == "HTTP_FROM" ||
	     name == "FROM" ||
	     name == "HTTP_VIA" ||
	     name == "VIA" ||
	     name == "HTTP_XROXY_CONNECTION" ||
	     name == "XROXY_CONNECTION" ||
	     name == "HTTP_PROXY_CONNECTION" ||
	     name == "PROXY_CONNECTION")
		{
		if ( session_http_info[c$id]$proxied_for == "" )
			session_http_info[c$id]$proxied_for = fmt("(%s::%s)", name, value);
		}
			
	# This is duplicating effort from the http-reply script, but it seems
	# worthwhile to do it here because we don't have to do as many function
	# calls since this is regularly done in http traffic.
	if ( name == "HOST" )
			session_http_info[c$id]$host = value;
	}
