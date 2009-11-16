@load global-ext
@load ftp

type ftp_ext_session_info: record {
	username: string &default="";
	password: string &default="";
	request_t: time &optional;
	url: string &default="";
	command: string &default="";
	reply_code: count &default=0;
	reply_msg: string &default="";
	
	# This is internal state tracking.
	ready: bool &default=F;
};

# Define the generic ftp-ext event that can be handled from other scripts
global ftp_ext: event(id: conn_id, si: ftp_ext_session_info);

module FTP;

export {
	global ftp_ext_sessions: table[conn_id] of ftp_ext_session_info &read_expire=5min;
}

function new_ftp_ext_session(): ftp_ext_session_info
	{
	local x: ftp_ext_session_info;
	return x;
	}

event ftp_request(c: connection, command: string, arg: string) &priority=10
	{
	if ( c$id !in ftp_ext_sessions ) 
		ftp_ext_sessions[c$id] = new_ftp_ext_session();
	
	local sess_ext = ftp_ext_sessions[c$id];
	
	# Throw the ftp_ext event if the session record is "ready".
	# This will make sure we get the last reply from the previous command.
	if ( sess_ext$ready )
		{
		# Copy the sess_ext variable because modifications to it can encounter
		# race conditions with the event dispatching system.
		event ftp_ext(c$id, copy(sess_ext));
		sess_ext$ready=F;
		}
	
	# Update the session's command everytime (after potentially dispatching
	# the ftp_ext event).
	sess_ext$command = command;
	
	if ( command == "RETR" || command == "STOR" )
		{
		local sess = ftp_sessions[c$id];
		
		# Move the request time into the ext session information
		sess_ext$request_t = sess$request_t;
		
		# If the start directory is unknown, record it as /.
		local pathfile = sub(absolute_path(sess, arg), /<unknown>/, "/.");
		
		sess_ext$url = fmt("ftp://%s%s", c$id$resp_h, pathfile);
		}
		
	else if ( command == "USER" )
		sess_ext$username=arg;

	else if ( command == "PASS" )
		sess_ext$password=arg;
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	# I'm not sure how I'd like to handle multiline responses yet.
	if ( cont_resp ) return;
	
	if ( c$id !in ftp_ext_sessions ) return;

	local sess_ext = ftp_ext_sessions[c$id];
	
	if ( sess_ext$command == "RETR" ||
	     sess_ext$command == "STOR" )
		{
		sess_ext$reply_code = code;
		sess_ext$reply_msg = msg;
		
		# We are considering the record "ready" once the reply has been recorded.
		sess_ext$ready = T;
		}
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in ftp_ext_sessions )
		{
		event ftp_ext(c$id, ftp_ext_sessions[c$id]);
		delete ftp_ext_sessions[c$id];
		}
	}

