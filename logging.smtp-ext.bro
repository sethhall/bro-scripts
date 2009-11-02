@load global-ext
@load smtp-ext

module SMTP;

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
	LOG::create_logs("smtp-ext", logging, split_log_file, T);
	LOG::define_header("smtp-ext", cat_sep("\t", "", 
	                                      "ts",
	                                      "orig_h", "orig_p",
	                                      "resp_h", "resp_p",
	                                      "helo", "message-id", "in-reply-to", 
	                                      "mailfrom", "rcptto",
	                                      "date", "from", "reply_to", "to",
	                                      "files", "last_reply", "x-originating-ip",
	                                      "path", "is_webmail", "agent"));
	}

event smtp_ext(id: conn_id, si: smtp_ext_session_info)
	{
	if ( si$mailfrom != "" )
		local log = LOG::get_file("smtp-ext", id$resp_h, F);
		print log, cat_sep("\t", "\\N",
		                   network_time(),
		                   id$orig_h, port_to_count(id$orig_p), id$resp_h, port_to_count(id$resp_p),
		                   si$helo,
		                   si$msg_id,
		                   si$in_reply_to,
		                   si$mailfrom,
		                   fmt_str_set(si$rcptto, /["'<>]|([[:blank:]].*$)/),
		                   si$date, 
		                   si$from, 
		                   si$reply_to, 
		                   fmt_str_set(si$to, /["']/),
		                   fmt_str_set(si$files, /["']/),
		                   si$last_reply, 
		                   si$x_originating_ip,
		                   si$path,
		                   si$is_webmail,
		                   si$agent);

	}