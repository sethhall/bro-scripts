@load http
@load http-request
@load http-ext

module HTTP;

type browser_header_info: record {
	name: string &default="";
	user_agent_regex: pattern;
	required_headers: vector of string;
	headers: vector of string;
	rev_headers: table[string] of int;
};

export {
	# Domains where header order is frequently messed up for various reasons.
	const ignore_header_order_at = /\.facebook\.com$/ | 
	                               /\.fbcdn\.net$/ |
	                               /\.apmebf\.com$/ |
	                               /\.qq\.com$/ |
	                               /\.yahoo\.com$/ |
	                               /\.mozilla\.com$/ |
	                               /\.google\.com$/ &redef;
	
	# This is a set of local proxies (proxies frequently rewrite headers)
	const local_http_proxies: set[addr] &redef;
}

const BROWSER_HEADERS: table[string] of browser_header_info = {
	["IE6"] = record($name = "IE6",
	                 $user_agent_regex = /Mozilla\/.*compatible; MSIE 6/ |
	                                     #/^iTunes\/.*Windows/ | /^Microsoft-CryptoAPI\// |
	                                     /Windows-Update-Agent/,
	                 $required_headers = vector("ACCEPT", "USER-AGENT", "CONNECTION"),
	                 $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "USER-AGENT", "CONNECTION"),
	                 $rev_headers = table([""]=0)),

	["IE7"] = record($name = "IE7",
	                 $user_agent_regex = /Mozilla\/.*compatible; MSIE 7/,
	                 $required_headers = vector("ACCEPT", "UA-CPU", "USER-AGENT", "CONNECTION"),
	                 $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "UA-CPU", "ACCEPT-ENCODING", "ACCEPT-CHARSET", "IF-MODIFIED-SINCE", "IF-NONE-MATCH", "USER-AGENT", "CONNECTION", "KEEP-ALIVE"),
	                 $rev_headers = table([""]=0)),
	
	["IE8"] = record($name = "IE8",
	                 $user_agent_regex = /Mozilla\/.*MSIE 8/ |
	                                     /Mozilla\/.*compatible; MSIE 7.*Trident\/4\.0/,
	                 $required_headers = vector("ACCEPT", "USER-AGENT", "UA-CPU",  "HOST", "CONNECTION"),
	                 $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "USER-AGENT", "UA-CPU", "ACCEPT-ENCODING", "HOST", "CONNECTION", "COOKIE"),
	                 $rev_headers = table([""]=0)),

	["MSOffice"] = record($name = "MSOffice",
	                 $user_agent_regex = /MSOffice/,
	                 $required_headers = vector("ACCEPT", "USER-AGENT", "UA-CPU", "CONNECTION"),
	                 $headers = vector("ACCEPT", "REFERER", "ACCEPT-LANGUAGE", "USER-AGENT", "UA-CPU", "ACCEPT-ENCODING", "CONNECTION", "COOKIE"),
	                 $rev_headers = table([""]=0)),

	["FIREFOX"] = record($name = "FIREFOX",
	                     $user_agent_regex = /Gecko\/.*(Firefox|Thunderbird|Netscape)\// |
	                                         /^mozbar [0-9\.]* xpi/,
	                     $required_headers = vector("USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "CONNECTION"),
	                     $headers = vector("HOST", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "ACCEPT-CHARSET", "CONTENT-TYPE", "REFERER", "CONTENT-LENGTH", "COOKIE", "RANGE", "CONNECTION"),
	                     $rev_headers = table([""]=0)),

	["WEBKIT_OSX_<=312"] = record($name="WEBKIT_OSX_<=312",
	                    $user_agent_regex = /(PPC|Intel) Mac OS X;.*Safari\//,
	                    $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE"),
	                    $headers = vector("HOST", "CONNECTION", "REFERER", "USER-AGENT", "IF-MODIFIED-SINCE", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE", "COOKIE"),
	                    $rev_headers = table([""]=0)),

	["WEBKIT_OSX_PPC"] = record($name = "WEBKIT_OSX_PPC",
	                    $user_agent_regex = /PPC Mac OS X.*AppleWebKit\/.*(Safari\/)?/,
	                    $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE"),
	                    $headers = vector("HOST", "CONNECTION", "REFERER", "USER-AGENT", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE"),
	                    $rev_headers = table([""]=0)),

	# ACCEPT was removed as a header because it is put in two different locations at different times.
	["WEBKIT_OSX_10.4"] = record($name = "WEBKIT_OSX_10.4",
	                    $user_agent_regex = /^AppleSyndication/ |
	                                        /Mac OS X.*AppleWebKit\/.*(Safari\/)?/,
	                    $required_headers = vector("ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "USER-AGENT", "CONNECTION"),
	                    $headers = vector("ACCEPT-LANGUAGE", "ACCEPT-ENCODING", "COOKIE", "REFERER", "USER-AGENT", "CONNECTION"),
	                    $rev_headers = table([""]=0)),
	
	["WEBKIT_OSX_10.5"] = record($name = "WEBKIT_OSX_10.5",
	                    $user_agent_regex = /^Apple-PubSub/ |
	                                        /CFNetwork\/.*Darwin\// |
	                                        /(Windows|Mac OS X|iPhone OS).*AppleWebKit\/.*(Safari\/)?/,
	                    $required_headers = vector("USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "CONNECTION"),
	                    $headers = vector("USER-AGENT", "REFERER", "ACCEPT", "ACCEPT-LANGUAGE", "COOKIE", "CONNECTION"),
	                    $rev_headers = table([""]=0)),
	
	["CHROME_<4.0"] = record($name = "CHROME_<4.0",
	                    $user_agent_regex = /Chrome\/.*Safari\//,
	                    $required_headers = vector("USER-AGENT", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "HOST", "CONNECTION"),
	                    $headers = vector("USER-AGENT", "REFERER", "CONTENT-LENGTH", "CONTENT-TYPE", "ACCEPT", "RANGE", "COOKIE", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET", "HOST", "CONNECTION"),
	                    $rev_headers = table([""]=0)),
	
	["CHROME_>=4.0"] = record($name = "CHROME_>=4.0",
	                    $user_agent_regex = /Chrome\/.*Safari\//,
	                    $required_headers = vector("HOST", "CONNECTION", "USER-AGENT", "ACCEPT", "ACCEPT-ENCODING", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET"),
	                    $headers = vector("HOST", "CONNECTION", "USER-AGENT", "REFERER", "CONTENT-LENGTH", "CONTENT-TYPE", "ACCEPT", "RANGE", "ACCEPT-ENCODING", "COOKIE", "ACCEPT-LANGUAGE", "ACCEPT-CHARSET"),
	                    $rev_headers = table([""]=0)),
	
	["FLASH"] = record($name = "FLASH",
	                   $user_agent_regex = /blah... nothing matches/,
	                   $required_headers = vector("ACCEPT", "ACCEPT-LANGUAGE", "REFERER", "X-FLASH-VERSION", "ACCEPT-ENCODING", "USER-AGENT", "COOKIE", "CONNECTION"),
	                   $headers = vector("ACCEPT", "ACCEPT-LANGUAGE", "REFERER", "X-FLASH-VERSION", "ACCEPT-ENCODING", "USER-AGENT", "COOKIE", "CONNECTION", "HOST"),
	                   $rev_headers = table([""]=0)),
};

# Generate all of the reverse header tables.
event bro_init()
	{
	for ( browser_name in BROWSER_HEADERS )
		{
		local browser = BROWSER_HEADERS[browser_name];
		delete browser$rev_headers[""];
		for ( i in browser$headers )
			{
			browser$rev_headers[browser$headers[i]] = i;
			}
		}
	}


const ordered_headers: set[string] = {
	"HOST",
	"USER-AGENT",
	"ACCEPT",
	"ACCEPT-LANGUAGE",
	"ACCEPT-ENCODING",
	"ACCEPT-CHARSET",
	"KEEP-ALIVE",
	"CONNECTION",
	"CONTENT-TYPE",
	"REFERER",
	"CONTENT-LENGTH",
	"COOKIE", 
	"RANGE",
	"UA-CPU",
	"X-FLASH-VERSION",
};

type header_tracker: record {
	ua_identified: set[string];
	identified: set[string];
	broken: set[string];
	possibles: table[string] of count;
};

global tracking_headers: table[conn_id] of header_tracker &read_expire=30secs;
global recently_examined: set[addr] &create_expire=30secs &redef;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( !is_orig || 
	     name !in ordered_headers ) 
		return;
	
	if ( !is_local_addr(c$id$orig_h) || 
	     #c$id$orig_h in recently_examined || 
	     c$id$orig_h in local_http_proxies ) 
		return;
	
	local header = name;
	if ( c$id !in tracking_headers )
		{
		tracking_headers[c$id] = [$ua_identified=set(""),
		                          $identified=set(""),
		                          $broken=set(""),
		                          $possibles=table(["IE6"]=0, ["IE7"]=0, ["IE8"]=0, ["MSOffice"]=0, ["FIREFOX"]=0, ["WEBKIT_OSX_PPC"]=0, ["WEBKIT_OSX_10.4"]=0, ["WEBKIT_OSX_10.5"]=0, ["CHROME_<4.0"]=0, ["CHROME_>=4.0"]=0, ["FLASH"]=0)];
		# FIXME: this is a hack because set("") above needed an empty element for some reason.
		delete tracking_headers[c$id]$identified[""];
		delete tracking_headers[c$id]$ua_identified[""];
		delete tracking_headers[c$id]$broken[""];
		}
		
	local ht = tracking_headers[c$id];
	
	#print fmt("CHECKING HEADER: %s", header);
	for ( browser_name in BROWSER_HEADERS )
		{
		if ( header == "USER-AGENT" )
			{
			if ( BROWSER_HEADERS[browser_name]$user_agent_regex in value )
				add ht$ua_identified[browser_name];
			}
		
		if ( browser_name !in ht$identified )
			{
			local browser = BROWSER_HEADERS[browser_name];
			
			if ( browser_name in ht$possibles && 
				 header in browser$rev_headers )
				{
				local possible_browser = ht$possibles[browser_name]; # count
				local browser_rev_headers = browser$rev_headers; # table[string] of int
				local h_position = browser_rev_headers[header]; # count
				local req_headers = browser$required_headers; # vector of string
				local next_required_header = req_headers[possible_browser+1]; # string
				local current_header_val = req_headers[h_position]; # string
				#print fmt("for browser: %s :: checking header: %s :: req position: %d :: next required: %s :: len of req headers: %d", browser_name, header, ht$possibles[browser_name], req_headers[ht$possibles[browser_name]+1], |req_headers|);
				
				if ( next_required_header == header )
					{
					++ht$possibles[browser_name];
					}
					
				
				else if ( possible_browser == 0 || possible_browser == |req_headers| ||
				          (browser_rev_headers[req_headers[possible_browser]] < h_position &&
				           h_position < browser_rev_headers[next_required_header]) )
					{
					#print fmt("%s is an optional header for %s (but it is in the correct position).", header, browser_name);
					}
				else
					{
					delete ht$possibles[browser_name];
					}

				# Have we found a browser yet?
				if ( browser_name in ht$possibles && 
					 ht$possibles[browser_name] == |req_headers| )
					{
					add ht$identified[browser_name];
					}
				}
			}
		}
	}

event http_ext(id: conn_id, si: http_ext_session_info) &priority=-10
	{
	if ( id in tracking_headers && 
	     id$orig_h !in local_http_proxies &&
	     si$proxied_for == "" )
		{
		add recently_examined[id$orig_h];
			
		if ( ignore_header_order_at in si$host )
			{
			#print "we're going to ignore this entire request.";
			return;
			}
		
		local is_matched = F;
		#if ( |tracking_headers[id]$identified| > 0 )
		#	{
 		#	is_matched = F;
		#	for ( b in tracking_headers[id]$identified )
		#		{
		#		if ( BROWSER_HEADERS[b]$user_agent_regex in si$user_agent )
		#			{
		#			is_matched = T;
		#			}
		#		}
		#	if ( !is_matched )
		#		{
		#		#print fmt("Headers look like %s, but User-Agent doesn't match.", fmt_str_set(tracking_headers[id]$identified, /blah/));
		#		print cat_sep("\t", "\\N",
		#		              si$start_time,
		#		              id$orig_h, port_to_count(id$orig_p),
		#		              id$resp_h, port_to_count(id$resp_p),
		#		              fmt_str_set(si$force_log_reasons, /DONTMATCH/),
		#		              si$method, si$url, si$referrer,
		#		              si$user_agent, si$proxied_for);
		#		}
		#	}
		
		# Do this in case the User-Agent is known, but the headers don't match it.
		is_matched=F;
		for ( b in tracking_headers[id]$ua_identified )
			{
			if ( b in tracking_headers[id]$identified )
				{
				is_matched=T;
				}
			}
		if ( |tracking_headers[id]$ua_identified| > 0 && !is_matched )
			{
			print fmt("User-Agent looks like %s, but headers look like %s.", fmt_str_set(tracking_headers[id]$ua_identified, /blah/), fmt_str_set(tracking_headers[id]$identified, /blah/));
			print cat_sep(" :: ", "\\N",
			              si$start_time,
			              id$orig_h, port_to_count(id$orig_p),
			              id$resp_h, port_to_count(id$resp_p),
			              fmt_str_set(si$force_log_reasons, /DONTMATCH/),
			              si$method, si$url, si$referrer,
			              si$user_agent, si$proxied_for);
			
			}
		}
	delete tracking_headers[id];
	}

