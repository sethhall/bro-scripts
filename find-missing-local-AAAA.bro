##! Find, measure, and log the number of missing AAAA records for incoming 
##! AAAA requests.  This can be used to create a priority list of domains
##! to enable with IPv6 since it will show the most frequently requested sites
##! that don't currently have IPv6.
##!
##! Notes::
##!   Site::local_zones must be configured in order for this script to work.
##!   This script requires a fix that is included in the git repository and 
##!   and should be in the master branch soon.  The version needs to be >2.1

@load base/frameworks/metrics

export {
	redef enum Metrics::ID += {
		MISSING_AAAA
	};
}

event bro_init()
	{
	Metrics::add_filter(MISSING_AAAA, [$break_interval=1hr]);
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( rec?$query && rec?$qtype && !rec?$answers &&
	     rec?$rcode && rec$rcode == 0 &&
	     rec$qtype == 28 &&
	     Site::is_local_name(rec$query) )
			{
			Metrics::add_data(MISSING_AAAA, [$str=rec$query], 1);
			}
	}
