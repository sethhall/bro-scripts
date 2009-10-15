@load global-ext
@load ftp

module FTP;

export {
	global ftp_ext_log = open_log_file("ftp-ext") &raw_output;
	
	type ftp_ext_session_info: record {
		last_url: string &default="";
		password: string &default="";
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
		# If an anonymous user logged in, record what they used as a password.
		local userpass = ( sess$user in guest_ids ) ?
							fmt("%s:%s", sess$user, sess_ext$password) :
							sess$user;
		
		# If the start directory is unknown, record it as ./
		local pathfile = sub(absolute_path(sess, arg), /<unknown>/, "/.");
		
		sess_ext$last_url = fmt("ftp://%s@%s%s", userpass, c$id$resp_h, pathfile);
		print cat_sep("\t", "\\N",
						sess$request_t,
						c$id$orig_h, fmt("%d", c$id$orig_p),
						c$id$resp_h, fmt("%d", c$id$resp_p),
						command, sess_ext$last_url);
		}
	}
	
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	#TODO: include reply in logged message
	local reply = "";
	if ( code in ftp_replies )
		 reply = ftp_replies[code];
		
	print code;
	print reply;
	}
	
event file_transferred(c: connection, prefix: string, descr: string, mime_type: string)
	{
	print descr;
	}

