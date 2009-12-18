@load global-ext

module KnownHosts;

export {
	# The hosts whose existence should be logged.
	# Choices are: LocalHosts, RemoteHosts, AllHosts
	const logging = LocalHosts &redef;
	
	# In case you are interested in more than logging just local assets
	# you can split the log file.
	const split_log_file = F &redef;
	
	# Maintain the list of known hosts for 24 hours so that the existence
	# of each individual address is logged each day.
	global known_hosts: set[addr] &create_expire=1day &synchronized &persistent;
}

event bro_init()
	{
	LOG::create_logs("known-hosts", logging, split_log_file, T);
	# Removed the header since it's fairly useless in this log.
	#LOG::define_header("known-hosts", cat_sep("\t", "", "host"));
	}

event connection_established(c: connection)
	{
	local id = c$id;
	
	local log:file;
	if ( id$orig_h !in known_hosts && addr_matches_hosts(id$orig_h, logging) )
		{
		log = LOG::get_file_by_addr("known-hosts", id$orig_h, F);
		add known_hosts[id$orig_h];
		print log, cat_sep("\t", "", id$orig_h);
		}
	if ( id$resp_h !in known_hosts && addr_matches_hosts(id$resp_h, logging) )
		{
		log = LOG::get_file_by_addr("known-hosts", id$resp_h, F);
		add known_hosts[id$resp_h];
		print log, cat_sep("\t", "", id$resp_h);
		}
	}
