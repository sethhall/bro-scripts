# Copyright 2008 Seth Hall <hall.692@osu.edu>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that: (1) source code distributions
# retain the above copyright notice and this paragraph in its entirety, (2)
# distributions including binary code include the above copyright notice and
# this paragraph in its entirety in the documentation or other materials
# provided with the distribution, and (3) all advertising materials mentioning
# features or use of this software display the following acknowledgement:
# ``This product includes software developed by the University of California,
# Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
# the University nor the names of its contributors may be used to endorse
# or promote products derived from this software without specific prior
# written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

@load global-ext

module KnownServices;

export {
	const services_log = open_log_file("known-services") &raw_output &redef;

	global known_services: set[addr, port] &create_expire=1day &synchronized &persistent;
	
	# The hosts whose services should be logged.
	const logged_hosts: Hosts = LocalHosts &redef;
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
		print services_log, cat_sep("\t", "\\N", id$resp_h, fmt("%d", id$resp_p), fmt_str_set(c$service, /-/));
		}
	}
	
event connection_state_remove(c: connection)
	{
	event known_services_done(c);
	}