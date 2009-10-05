@load global-ext

@load ftp

module FTP;

export {
	global ftp_ext_log = open_log_file("ftp-ext") &raw_output;
	
	type ftp_ext_session_info: record {
		url: string &default="";
		password: string &default="";
		mimetype: string &default="";
	};
	
	global ftp_ext_sessions: table[conn_id] of ftp_ext_session_info &write_expire=1min;
}

function new_ftp_ext_session(): ftp_ext_session_info
	{
	local blah: ftp_ext_session_info;
	return blah;
	}

event ftp_request(c: connection, command: string, arg: string) &priority=10
	{
	if ( c$id !in ftp_ext_sessions ) 
		ftp_ext_sessions[c$id] = new_ftp_ext_session();
		
	local sess = ftp_sessions[c$id];
	local sess_ext = ftp_ext_sessions[c$id];
	
	if ( command == "PASS" )
		sess_ext$password=arg;
	
	if ( command == "RETR" || command == "STOR" )
		{
		local userpass = ( /^(anonymous|ftp)$/ in sess$user ) ?
							fmt("%s:%s", sess$user, sess_ext$password) :
							sess$user;
		sess_ext$url = fmt("ftp://%s@%s%s", userpass, c$id$resp_h, absolute_path(sess, arg));
		print ftp_ext_log, cat_sep("\t", "\\N",
						sess$request_t,
						c$id$orig_h, fmt("%d", c$id$orig_p),
						c$id$resp_h, fmt("%d", c$id$resp_p),
						command, sess_ext$url);
		}
	}
	
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	#TODO: include reply in logged message
	local reply = "";
	if ( code in ftp_replies )
		 reply = ftp_replies[code];
	}
