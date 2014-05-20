##! Find and log the top websites being accessed.

@load base/utils/site
@load base/frameworks/sumstats
@load base/protocols/http

module TopWebsites;

export {
	## How many of the top websites should be logged.
	const top_k = 25 &redef;

	## How often the log should be written.
	const logging_interval = 5mins &redef;

	## The log ID.
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:           time             &log;
		ts_delta:     interval         &log;
		where:        string           &log;
		top_sites:    vector of string &log;
		top_counts:   vector of string &log;
		top_epsilons: vector of string &log;
	};
}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);

	local r1 = SumStats::Reducer($stream="http.top-sites", 
	                             $apply=set(SumStats::TOPK), 
	                             $topk_size=top_k*10);
	SumStats::create([$name="find-top-websites",
	                  $epoch=logging_interval,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http.top-sites"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, top_k);

	                  	local top_sites = string_vec();
	                  	local top_counts = index_vec();
	                  	local top_epsilons = index_vec();
	                  	local i = 0;
	                  	for ( element in s ) 
	                  		{
	                  		top_sites[|top_sites|] = s[element]$str;
	                  		top_counts[|top_counts|] = topk_count(r$topk, s[element]);
	                  		top_epsilons[|top_epsilons|] = topk_epsilon(r$topk, s[element]);

	                  		if ( ++i == top_k )
	                  			break;
	                  		}
	                  	Log::write(LOG, [$ts=ts, 
	                  	                 $ts_delta=logging_interval,
	                  	                 $where=key$str,
	                  	                 $top_sites=top_sites,
	                  	                 $top_counts=top_counts,
	                  	                 $top_epsilons=top_epsilons]);
	                  	}
	                 ]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( rec?$host )
		{
		local where = Site::is_local_addr(rec$id$resp_h) ? "local" : "remote";
		SumStats::observe("http.top-sites", [$str=where], [$str=rec$host]);
		}
	}
