@load global-ext

module KnownServices;

export {
	const services_log = open_log_file("known-services") &raw_output &redef;

	global known_services: set[addr, port] &create_expire=1day &synchronized &persistent;
	
	# The hosts whose services should be logged.
	const logged_hosts = LocalHosts &redef;
}

# The temporary holding place for new, unknown services.
global established_conns: set[addr, port] &create_expire=1day &redef;

event connection_established(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in established_conns && 
	     addr_matches_hosts(id$resp_h, logged_hosts) )
		add established_conns[id$resp_h, id$resp_p];
	}
	
event known_services_done(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in known_services &&
	     [id$resp_h, id$resp_p] in established_conns &&
	     "ftp-data" !in c$service ) # don't include ftp data sessions
		{
		add known_services[id$resp_h, id$resp_p];
		print services_log, cat_sep("\t", "\\N", 
		                            id$resp_h, port_to_count(id$resp_p), 
		                            fmt_str_set(c$service, /-/));
		}
	}
	
event connection_state_remove(c: connection)
	{
	event known_services_done(c);
	}