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
	}

event smtp_ext(id: conn_id, si: smtp_ext_session_info)
	{
	local log = LOG::choose("smtp-ext", id$resp_h);
	if ( si$mailfrom != "" )
		print log, cat_sep("\t", "\\N",
		                   network_time(),
		                   id$orig_h, fmt("%d", id$orig_p), id$resp_h, fmt("%d", id$resp_p),
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