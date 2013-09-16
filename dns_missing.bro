##! Find, measure, and log the number of missing DNS records for incoming 
##! requests.  This can be used to create a priority list of domains
##! to enable with IPv6 since it will show the most frequently requested sites
##! that don't currently have IPv6.
##!
##! Notes::
##!   Site::local_zones must be configured in order for this script to work.

@load base/utils/site
@load base/frameworks/sumstats

module DnsMissing;

export {
	## How many of the top missing names should be logged.
	const top_k = 10 &redef;

	## How often the log should be written.
	const logging_interval = 1min &redef;

	## The records that should be tracked and logged.
	const records: set[string] = { 
		"A",
		"CNAME",
		"AAAA",
	} &redef;

	## The log ID.
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:           time             &log;
		ts_delta:     interval         &log;
		record_type:  string           &log;
		top_queries:  vector of string &log;
		top_counts:   vector of string &log;
		top_epsilons: vector of string &log;
	};
}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);

	local r1 = SumStats::Reducer($stream="dns.aaaa.missing", 
	                             $apply=set(SumStats::TOPK), 
	                             $topk_size=top_k*10);
	SumStats::create([$name="find-missing-aaaa",
	                  $epoch=logging_interval,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["dns.aaaa.missing"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, top_k);

	                  	local top_queries = string_vec();
	                  	local top_counts = index_vec();
	                  	local top_epsilons = index_vec();
	                  	local i = 0;
	                  	for ( element in s ) 
	                  		{
	                  		top_queries[|top_queries|] = s[element]$str;
	                  		top_counts[|top_counts|] = topk_count(r$topk, s[element]);
	                  		top_epsilons[|top_epsilons|] = topk_epsilon(r$topk, s[element]);

	                  		if ( ++i == top_k )
	                  			break;
	                  		}

	                  	Log::write(LOG, [$ts=ts, 
	                  	                 $ts_delta=logging_interval, 
	                  	                 $record_type=key$str,
	                  	                 $top_queries=top_queries, 
	                  	                 $top_counts=top_counts, 
	                  	                 $top_epsilons=top_epsilons]);
	                  	}
	                 ]);
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( rec?$query && rec?$qtype && !rec?$answers &&
	     rec?$rcode && rec$rcode == 0 &&
	     rec$qtype_name in records &&
	     Site::is_local_name(rec$query) )
			{
			SumStats::observe("dns.aaaa.missing", [$str=rec$qtype_name], [$str=rec$query]);
			}
	}
