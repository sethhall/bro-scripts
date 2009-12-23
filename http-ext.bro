@load global-ext
@load http-request
@load http-entity

type http_ext_session_info: record {
	start_time: time;
	method: string &default="";
	host: string &default="";
	uri: string &default="";
	url: string &default="";
	referrer: string &default="";
	user_agent: string &default="";
	proxied_for: string &default="";

	force_log: bool &default=F; # This will force the request to be logged (if doing any logging)
	force_log_client_body: bool &default=F; # This will force the client body to be logged.
	force_log_reasons: set[string]; # Reasons why the forced logging happened.
	
	# This is internal state tracking.
	full: bool &default=F;
	new_user_agent: bool &default=F;
};

function default_http_ext_session_info(): http_ext_session_info
	{
	local x: http_ext_session_info;
	local tmp: set[string] = set();
	x$start_time=network_time();
	x$force_log_reasons=tmp;
	return x;
	}

type http_ext_activity_count: record {
	sql_injections: track_count;
	sql_injection_probes: track_count;
	suspicious_posts: track_count;
};

function default_http_ext_activity_count(a:addr):http_ext_activity_count 
	{
	local x: http_ext_activity_count; 
	return x; 
	}

# Define the generic http_ext events that can be handled from other scripts
global http_ext: event(id: conn_id, si: http_ext_session_info);

module HTTP;

# Uncomment the following lines if you have these data sets available and would
# like to use them.
#@load malware_com_br_block_list-data
#@load zeus-data
#@load malwaredomainlist-data

export {
	redef enum Notice += { 
		HTTP_Suspicious,
		HTTP_SQL_Injection_Attack,
		HTTP_SQL_Injection_Heavy_Probing,

		HTTP_Malware_com_br_Block_List,
		HTTP_Zeus_Communication,
		HTTP_MalwareDomainList_Communication,
	};

	# This is the regular expression that is used to match URI based SQL injections
	const sql_injection_regex = 
		  /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])[^a-zA-Z&]/
		| /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([oO][rR]|[aA][nN][dD])([[:blank:]]|\/\*.*?\*\/)+['"]?[^a-zA-Z&]+?=/
		| /[\?&][^[:blank:]]+?=[\-0-9%]*([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/)*(\-|\+|\|\|)([[:blank:]]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\|]+?=([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/|;)*([oO][rR]|[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT]|\()[^a-zA-Z&]/
		| /[\?&][^[:blank:]]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/ &redef;

	# SQL injection probes are considered to be:
	#  1. A single single-quote at the end of a URL with no other single-quotes.
	#  2. URLs with one single quote at the end of a normal GET value.
	const sql_injection_probe_regex =
		  /^[^\']+\'$/
		| /^[^\']+\'&[^\']*$/ &redef;

	# Define which hosts user-agents you'd like to track.
	const track_user_agents_for = LocalHosts &redef;

	# If there is something creating large number of strange user-agent,
	# you can filter those out with this pattern.
	const ignored_user_agents = /DONT_MATCH_ANYTHING/ &redef;

	# HTTP post data contents that appear suspicious.
	#  This is usually spammy forum postings and the like.
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
		
		const http_forwarded_headers = {
		  "HTTP_FORWARDED",
		  "FORWARDED",
		  "HTTP_X_FORWARDED_FOR",
		  "X_FORWARDED_FOR",
		  "HTTP_X_FORWARDED_FROM",
		  "X_FORWARDED_FROM",
		  "HTTP_CLIENT_IP",
		  "CLIENT_IP",
		  "HTTP_FROM",
		  "FROM",
		  "HTTP_VIA",
		  "VIA",
		  "HTTP_XROXY_CONNECTION",
		  "XROXY_CONNECTION",
		  "HTTP_PROXY_CONNECTION",
		  "PROXY_CONNECTION",
		} &redef;

	global conn_info: table[conn_id] of http_ext_session_info 
		&read_expire=5mins
		&redef;

	global activity_counters: table[addr] of http_ext_activity_count 
		&create_expire=1day 
		&synchronized
		&default=default_http_ext_activity_count
		&redef;

	# You can inspect this during runtime from other modules to see what
	# user-agents a host has used.
	global known_user_agents: table[addr] of set[string] 
		&create_expire=3hrs
		&synchronized
		&default=addr_empty_string_set
		&redef;
}

# This is called from signatures (theoretically)
function log_post(state: signature_state, data: string): bool
	{
	# Log the post data when it becomes available.
	if ( state$conn$id in conn_info )
		{
		conn_info[state$conn$id]$force_log_client_body = T;
		add conn_info[state$conn$id]$force_log_reasons[fmt("matched_signature_%s",state$id)];
		}
	
	# We'll always allow the signature to fire
	return T;
	}
	
event http_request(c: connection, method: string, original_URI: string,
	               unescaped_URI: string, version: string)
	{
	if ( c$id !in conn_info )
		{
		local x = default_http_ext_session_info();
		conn_info[c$id] = x;
		}
	
	local sess_ext = conn_info[c$id];
	sess_ext$method = method;
	sess_ext$uri = unescaped_URI;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=5
	{
	if ( !is_orig )
		return; 

	local id = c$id;
	if ( id !in conn_info )
		return;
	
	local sess_ext = conn_info[id];
	sess_ext$url = fmt("http://%s%s", sess_ext$host, sess_ext$uri);

	# Detect and log SQL injection attempts in their own log file
	if ( sql_injection_regex in sess_ext$uri )
		{
		sess_ext$force_log=T;
		add sess_ext$force_log_reasons["sql_injection"];
		
		++(activity_counters[id$orig_h]$sql_injections$n);
		
		if ( default_check_threshold(activity_counters[id$orig_h]$sql_injections) )
			{
			NOTICE([$note=HTTP_SQL_Injection_Attack,
			        $msg=fmt("SQL injection attack (n=%d): %s -> %s",
			                 activity_counters[id$orig_h]$sql_injections$n,
			                 numeric_id_string(id), sess_ext$url),
			        $conn=c,
			        $n=activity_counters[id$orig_h]$sql_injections$n]);
			}
		}
	if ( sql_injection_probe_regex in sess_ext$uri )
		{
		sess_ext$force_log=T;
		add sess_ext$force_log_reasons["sql_injection_probe"];
		++(activity_counters[id$orig_h]$sql_injection_probes$n);
		
		if ( default_check_threshold(activity_counters[c$id$orig_h]$sql_injection_probes) )
			{
			NOTICE([$note=HTTP_SQL_Injection_Heavy_Probing, 
			        $msg=fmt("Heavy probing from %s", id$orig_h), 
			        $n=activity_counters[c$id$orig_h]$sql_injection_probes$n, 
			        $conn=c]);
			}
		}
	
@ifdef ( MalwareComBr_BlockList )
	if ( MalwareComBr_BlockList in sess_ext$url )
		{
		sess_ext$force_log=T;
		sess_ext$force_log_client_body=T;
		add sess_ext$force_log_reasons["malware_com_br"];
		local malware_com_br_msg = fmt("%s %s %s", sess_ext$method, sess_ext$url, sess_ext$referrer);
		NOTICE([$note=HTTP_Malware_com_br_Block_List, $msg=malware_com_br_msg, $conn=c]);
		}
@endif

@ifdef ( ZeusDomains )
	if ( sess_ext$host in ZeusDomains )
		{
		sess_ext$force_log=T;
		sess_ext$force_log_client_body=T;
		add sess_ext$force_log_reasons["zeustracker"];
		local zeus_msg = fmt("%s communicated with likely Zeus controller at %s", c$id$orig_h, sess_ext$host);
		NOTICE([$note=HTTP_Zeus_Communication, $msg=zeus_msg, $sub=sess_ext$url, $conn=c]);
		}
@endif

@ifdef ( MalwareDomainList )
	if ( sess_ext$url in MalwareDomainList )
		{
		sess_ext$force_log=T;
		sess_ext$force_log_client_body=T;
		add sess_ext$force_log_reasons["malwaredomainlist"];
		local mdl_msg = fmt("%s communicated with malwaredomainlist.com URL at %s", c$id$orig_h, sess_ext$url);
		NOTICE([$note=HTTP_MalwareDomainList_Communication, $msg=mdl_msg, $sub=MalwareDomainList[sess_ext$url], $conn=c]);
		}
@endif

	event http_ext(id, sess_ext);
	
	# No data from the reply is supported yet, so it's ok to delete here.
	delete conn_info[c$id];
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( !is_orig ) return;

	if ( c$id !in conn_info )
		conn_info[c$id] = default_http_ext_session_info();

	local ci = conn_info[c$id];

	if ( name == "REFERER" )
		ci$referrer = value;
		
	else if ( name == "HOST" )
		ci$host = value;

	else if ( name == "USER-AGENT" )
		{
		ci$user_agent = value;
		
		if ( ignored_user_agents in value ) 
			return;
			
		if ( addr_matches_hosts(c$id$orig_h, track_user_agents_for) ||
			 value in known_user_agents[c$id$orig_h] )
			{
			if ( c$id$orig_h !in known_user_agents )
				{
				known_user_agents[c$id$orig_h] = set();
				ci$new_user_agent = T;
				}
			add known_user_agents[c$id$orig_h][value];
			}
		}

	else if ( name in http_forwarded_headers )
		{
		if ( ci$proxied_for == "" )
			ci$proxied_for = fmt("(%s::%s)", name, value);
		else
			ci$proxied_for = fmt("%s, (%s::%s)", ci$proxied_for, name, value);
		}
	}
