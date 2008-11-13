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
	
	if ( !addr_matches_hosts(c$id$resp_h, logged_hosts) )
		return;
	
	lookup_ssl_conn(c, "ssl_certificate", T);
	local conn = ssl_connections[c$id];
	if ( [c$id$resp_h, c$id$resp_p, cert$subject] !in certs )
		{
		add certs[c$id$resp_h, c$id$resp_p, cert$subject];
		print log, cat_sep("\t", "\\N", c$id$resp_h, fmt("%d", c$id$resp_p), cert$subject);
		}
	}

