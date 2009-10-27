@load smtp
@load global-ext

module SMTP;

export {
	global smtp_ext_log = open_log_file("smtp-ext") &raw_output &redef;

	redef enum Notice += { 
		# Thrown when a local host receives a reply mentioning an smtp block list
		SMTP_BL_Error_Message, 
		# Thrown when the local address is seen in the block list error message
		SMTP_BL_Blocked_Host, 
		# When mail seems to originate from a suspicious location
		SMTP_Suspicious_Origination,
	};
	
	# Uncomment this next line or define it in your own file to totally 
	# disable inspection into the smtp received from headers.
	#   Disabling supressses the suspicious_origination notice when it's 
	#   tracked through the received from headers.
	const smtp_capture_mail_path = 1;
	
	# Direction to capture the full "Received from" path. (from the Direction enum)
	#    RemoteHosts - only capture the path until an internal host is found.
	#    LocalHosts - only capture the path until the external host is discovered.
	#    AllHosts - capture the entire path.
	const mail_path_capture: Hosts = LocalHosts &redef;
	
	# Places where it's suspicious for mail to originate from.
	#  this requires all-capital letter, two character country codes (e.x. US)
	const suspicious_origination_countries: set[string] = {} &redef;
	const suspicious_origination_networks: set[subnet] = {} &redef;

	# This matches content in SMTP error messages that indicate some
	# block list doesn't like the connection/mail.
	const smtp_bl_error_messages = 
	    /spamhaus\.org\//
	  | /sophos\.com\/security\//
	  | /spamcop\.net\/bl/
	  | /cbl\.abuseat\.org\// 
	  | /sorbs\.net\// 
	  | /bsn\.borderware\.com\//
	  | /mail-abuse\.com\//
	  | /bbl\.barracudacentral\.com\//
	  | /psbl\.surriel\.com\// 
	  | /antispam\.imp\.ch\// 
	  | /dyndns\.com\/.*spam/
	  | /rbl\.knology\.net\//
	  | /intercept\.datapacket\.net\// &redef;
}

type session_info: record {
	msg_id: string &default="";
	in_reply_to: string &default="";
	helo: string &default="";
	mailfrom: string &default="";
	rcptto: set[string];
	date: string &default="";
	from: string &default="";
	to: set[string];
	reply_to: string &default="";
	subject: string &default="";
	x_originating_ip: string &default="";
	received_from_originating_ip: string &default="";
	last_reply: string &default=""; # last message the server sent to the client
	files: string &default="";
	path: string &default="";
	current_header: string &default="";
};

# Define the generic smtp-ext event that can be handled from other scripts
global smtp_ext: event(id: conn_id, cl: session_info);

function default_session_info(): session_info
	{
	local tmp: set[string] = set();
	local tmp2: set[string] = set();
	return [$rcptto=tmp, $to=tmp2];
	}
# TODO: setting a default function doesn't seem to be working correctly here.
global conn_info: table[conn_id] of session_info &read_expire=4mins;

global in_received_from_headers: set[conn_id] &create_expire = 2min;
global smtp_received_finished: set[conn_id] &create_expire = 2min;
global smtp_forward_paths: table[conn_id] of string &create_expire = 2min &default = "";

# Examples for how to handle notices from this script.
#     (define these in a local script)...
#redef notice_policy += {
#	# Send email if a local host is on an SMTP watch list
#	[$pred(n: notice_info) = 
#		{ return (n$note == SMTP::SMTP_BL_Blocked_Host && is_local_addr(n$conn$id$orig_h)); },
#	 $result = NOTICE_EMAIL],
#};

function find_address_in_smtp_header(header: string): string
{
	local ips = find_ip_addresses(header);
		
	if ( |ips| > 1 )
		return ips[2];
	if ( |ips| > 0 )
		return ips[1];
	return "";
}

@ifdef( smtp_capture_mail_path )
# This event handler builds the "Received From" path by reading the 
# headers in the mail
event smtp_data(c: connection, is_orig: bool, data: string)
	{
	local id = c$id;

	if ( id !in conn_info ||
		 id !in smtp_sessions ||
		 !smtp_sessions[id]$in_header || 
		 id in smtp_received_finished)
		return;
		
	local conn_log = conn_info[id];

	if ( /^[rR][eE][cC][eE][iI][vV][eE][dD]:/ in data ) 
		add in_received_from_headers[id];
	else if ( /^[[:blank:]]/ !in data )
		delete in_received_from_headers[id];
	
	if ( id in in_received_from_headers ) # currently seeing received from headers
		{
		local text_ip = find_address_in_smtp_header(data);

		if ( text_ip == "" )
			return;
			
		local ip = to_addr(text_ip);
		
		# I don't care if mail bounces around on localhost
		if ( ip == 127.0.0.1 ) return;
		
		# This overwrites each time.
		conn_log$received_from_originating_ip = text_ip;
		
		local ellipsis = "";
		if ( !addr_matches_hosts(ip, mail_path_capture) && 
		     ip !in private_address_space )
			{
			ellipsis = "... ";
			add smtp_received_finished[id];
			}

		if (conn_log$path == "")
			conn_log$path = fmt("%s%s -> %s -> %s", ellipsis, ip, id$orig_h, id$resp_h);
		else
			conn_log$path = fmt("%s%s -> %s", ellipsis, ip, conn_log$path);
		}
	else if ( !smtp_sessions[id]$in_header && id !in smtp_received_finished ) 
		add smtp_received_finished[id];
	}
@endif

function end_smtp_extended_logging(c: connection)
	{
	local id = c$id;
	local conn_log = conn_info[id];
	
	local loc: geo_location;
	local ip: addr;
	if ( conn_log$x_originating_ip != "" )
		{
		ip = to_addr(conn_log$x_originating_ip);
		loc = lookup_location(ip);
	
		if ( loc$country_code in suspicious_origination_countries ||
			 ip in suspicious_origination_networks )
			{
			NOTICE([$note=SMTP_Suspicious_Origination,
				    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
				    $sub=fmt("Subject: %s", conn_log$subject),
				    $conn=c]);
			}
		}
		
	if ( conn_log$received_from_originating_ip != "" &&
	     conn_log$received_from_originating_ip != conn_log$x_originating_ip )
		{
		ip = to_addr(conn_log$received_from_originating_ip);
		loc = lookup_location(ip);
	
		if ( loc$country_code in suspicious_origination_countries ||
			 ip in suspicious_origination_networks )
			{
			NOTICE([$note=SMTP_Suspicious_Origination,
				    $msg=fmt("An email originated from %s (%s).", loc$country_code, ip),
				    $sub=fmt("Subject: %s", conn_log$subject),
					$conn=c]);
			}
		}

	if ( conn_log$mailfrom != "" )
		print smtp_ext_log, cat_sep("\t", "\\N", 
		                            network_time(), 
		                            id$orig_h, fmt("%d", id$orig_p), id$resp_h, fmt("%d", id$resp_p),
		                            conn_log$helo, 
		                            conn_log$msg_id, 
		                            conn_log$in_reply_to, 
		                            conn_log$mailfrom, 
		                            fmt_str_set(conn_log$rcptto, /["'<>]|([[:blank:]].*$)/),
		                            conn_log$date, 
		                            conn_log$from, 
		                            conn_log$reply_to, 
		                            fmt_str_set(conn_log$to, /["']/),
		                            gsub(conn_log$files, /["']/, ""),
		                            conn_log$last_reply, 
		                            conn_log$x_originating_ip,
		                            conn_log$path);
		
	event smtp_ext(id, conn_log);

	delete conn_info[id];
	delete smtp_received_finished[id];
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool)
	{
	local id = c$id;
	# This continually overwrites, but we want the last reply, so this actually works fine.
	if ( (code != 421 && code >= 400) && 
	     id in conn_info )
		{
		conn_info[id]$last_reply = fmt("%d %s", code, msg);

		# Raise a notice when an SMTP error about a block list is discovered.
		if ( smtp_bl_error_messages in msg )
			{
			local note = SMTP_BL_Error_Message;
			local message = fmt("%s received an error message mentioning an SMTP block list", c$id$orig_h);

			# Determine if the originator's IP address is in the message.
			local ips = find_ip_addresses(msg);
			local text_ip = "";
			if ( |ips| > 0 && to_addr(ips[1]) == c$id$orig_h )
				{
				note = SMTP_BL_Blocked_Host;
				message = fmt("%s is on an SMTP block list", c$id$orig_h);
				}
			
			NOTICE([$note=note,
			        $conn=c,
			        $msg=message,
			        $sub=msg]);
			}
		}
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=-5
	{
	local id = c$id;
	if ( id !in smtp_sessions )
		return;
		
	# In case this is not the first message in a session
	if ( ((/^[mM][aA][iI][lL]/ in command && /^[fF][rR][oO][mM]:/ in arg) ) &&
	     id in conn_info )
		{
		local tmp_helo = conn_info[id]$helo;
		end_smtp_extended_logging(c);
		conn_info[id] = default_session_info();
		conn_info[id]$helo = tmp_helo;
		}
		
	if ( id !in conn_info )  
		conn_info[id] = default_session_info();
	local conn_log = conn_info[id];
	
	if ( /^([hH]|[eE]){2}[lL][oO]/ in command )
		conn_log$helo = arg;
	
	if ( /^[rR][cC][pP][tT]/ in command && /^[tT][oO]:/ in arg )
		add conn_log$rcptto[split1(arg, /:[[:blank:]]*/)[2]];
	
	if ( /^[mM][aA][iI][lL]/ in command && /^[fF][rR][oO][mM]:/ in arg )
		{
		local partially_done = split1(arg, /:[[:blank:]]*/)[2];
		conn_log$mailfrom = split1(partially_done, /[[:blank:]]/)[1];
		}
	}

event smtp_data(c: connection, is_orig: bool, data: string) &priority=-5
	{
	local id = c$id;
		
	if ( id !in conn_info )
	return; 
    
	if ( !smtp_sessions[id]$in_header )
		{
		if ( /^[cC][oO][nN][tT][eE][nN][tT]-[dD][iI][sS].*[fF][iI][lL][eE][nN][aA][mM][eE]/ in data )
			{
			data = sub(data, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=/, "");
			if ( conn_info[id]$files == "" )
				conn_info[id]$files = data;
			else
				conn_info[id]$files += fmt(", %s", data);
			}
		return;
		}

	local conn_log = conn_info[id];	
	# This is to fully construct headers that will tend to wrap around.
	if ( /^[[:blank:]]/ in data )
		{
		data = sub(data, /^[[:blank:]]/, "");
		if ( conn_log$current_header == "message-id" )
			conn_log$msg_id += data;
		else if ( conn_log$in_reply_to == "in-reply-to" )
			conn_log$in_reply_to += data;
		else if ( conn_log$current_header == "subject" )
			conn_log$subject += data;
		else if ( conn_log$current_header == "from" )
			conn_log$from += data;
		else if ( conn_log$current_header == "reply-to" )
			conn_log$reply_to += data;
		return;
		}
	conn_log$current_header = "";

	if ( /^[mM][eE][sS][sS][aA][gG][eE]-[iI][dD]:/ in data )
		{
		conn_log$msg_id = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "message-id";
		}
	else if ( /^[iI][nN]-[rR][eE][pP][lL][yY]-[tT][oO]:/ in data )
		{
		conn_log$in_reply_to = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "in-reply-to";
		}

	else if ( /^[dD][aA][tT][eE]:/ in data )
		{
		conn_log$date = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "date";
		}

	else if ( /^[fF][rR][oO][mM]:/ in data )
		{
		conn_log$from = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "from";
		}

	else if ( /^[tT][oO]:/ in data )
		{
		add conn_log$to[split1(data, /:[[:blank:]]*/)[2]];
		conn_log$current_header = "to";
		}

	else if ( /^[rR][eE][pP][lL][yY]-[tT][oO]:/ in data )
		{
		conn_log$reply_to = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "reply-to";
		}

	else if ( /^[sS][uU][bB][jJ][eE][cC][tT]:/ in data )
		{
		conn_log$subject = split1(data, /:[[:blank:]]*/)[2];
		conn_log$current_header = "subject";
		}

	else if ( /^[xX]-[oO][rR][iI][gG][iI][nN][aA][tT][iI][nN][gG]-[iI][pP]:/ in data )
		{
		conn_log$x_originating_ip = find_ip_addresses(data)[1];
		conn_log$current_header = "x-originating-ip";
		}
	
	}

event connection_finished(c: connection) &priority=5
	{
	if ( c$id in conn_info )
		end_smtp_extended_logging(c);
	}

event connection_state_remove(c: connection) &priority=5
	{
	if ( c$id in conn_info )
		end_smtp_extended_logging(c);
	}
