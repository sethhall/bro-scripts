@load global-ext
@load ftp-ext

module FTP;

export {
	# If set to T, this will split inbound and outbound transactions
	# into separate files.  F merges everything into a single file.
	const split_log_file = F &redef;
	# Which mail transactions to log.
	# Choices are: Inbound, Outbound, All
	const logging = All &redef;
}

event bro_init()
	{
	LOG::create_logs("ftp-ext", logging, split_log_file, T);
	LOG::define_header("ftp-ext", cat_sep("\t", "", 
	                                      "ts",
	                                      "orig_h", "orig_p",
	                                      "resp_h", "resp_p",
	                                      "username", "password",
	                                      "command", "url",
	                                      "reply_code", "reply", "reply_message"));
	}

event ftp_ext(id: conn_id, si: ftp_ext_session_info) &priority=-10
	{
	local log = LOG::get_file_by_id("ftp-ext", id, F);
	
	local reply = "";
	if ( si$reply_code in ftp_replies )
		 reply = ftp_replies[si$reply_code];

	print log, cat_sep("\t", "\\N",
	                   si$request_t,
	                   id$orig_h, port_to_count(id$orig_p),
	                   id$resp_h, port_to_count(id$resp_p),
	                   si$username, 
	                   ( si$username in guest_ids ) ? si$password : "",
	                   si$command, si$url,
	                   si$reply_code, reply, si$reply_msg);

	}