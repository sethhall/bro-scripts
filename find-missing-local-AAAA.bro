##! Find, measure, and log the number of missing AAAA records for incoming 
##! AAAA requests.  This can be used to create a priority list of domains
##! to enable with IPv6 since it will show the most frequently requested sites
##! that don't currently have IPv6.
##!
##! There is an assumption being made that Bro is seeing external authoritative 
##! requests for your local DNS zones.

@load base/frameworks/metrics

export {
	redef enum Metrics::ID += {
		MISSING_AAAA
	};
}

event bro_init()
	{
	Metrics::add_filter(MISSING_AAAA, [$break_interval=1hour]);
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( rec?$rcode && rec$rcode == 0 && 
	     rec?$qtype && rec$qtype == 28 &&
	     ! rec?$answers &&
	     Site::is_local_addr(rec$id$resp_h) &&
	     ! Site::is_local_addr(rec$id$orig_h) )
			{
			Metrics::add_data(MISSING_AAAA, [$str=rec$query], 1);
			}
	}