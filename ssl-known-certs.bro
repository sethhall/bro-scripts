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
@load ssl

module SSL_KnownCerts;

export {
	const log = open_log_file("ssl-known-certs") &raw_output &redef;

	# The list of all detected certs.  This prevents over-logging.
	global certs: set[addr, port, string] &create_expire=1day &synchronized;
	
	# The hosts that should be logged.
	const logged_hosts: Hosts = LocalHosts &redef;
}

event ssl_certificate(c: connection, cert: X509, is_server: bool)
	{
	# The ssl analyzer doesn't do this yet, so let's do it here.
	add c$service["SSL"];
	
	if ( !ip_matches_hosts(c$id$resp_h, logged_hosts) )
		return;
	
	lookup_ssl_conn(c, "ssl_certificate", T);
	local conn = ssl_connections[c$id];
	if ( [c$id$resp_h, c$id$resp_p, cert$subject] !in certs )
		{
		add certs[c$id$resp_h, c$id$resp_p, cert$subject];
		print log, cat_sep("\t", "\\N", c$id$resp_h, fmt("%d", c$id$resp_p), cert$subject);
		}
	}

