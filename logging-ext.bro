module LOG;

export {
	# The record type to store logging information.
	type log_info: record {
		dh:           Directions_and_Hosts &default=All;
		split:        bool                 &default=F;
		raw_output:   bool                 &default=F;
		header:       string               &default="";
		files:        table[string] of file;
		tags:         set[string];
	};
	
	# Where the data for knowing how to log is stored.
	const logs: table[string] of log_info &redef;

	# Utility functions
	global get_file_by_addr: function(a: string, ip: addr, force_log: bool): file;
	global get_file_by_id: function(a: string, id: conn_id, force_log: bool): file;
	global print_log_by_addr: function(a: string, ip: addr, force_log: bool, tags: set[string], line: string): count;
	global print_log_by_id: function(a: string, id: conn_id, force_log: bool, tags: set[string], line: string): count;
	global open_log_files: function(a: string, tag: string);
	global create_logs: function(a: string, d: Directions_and_Hosts, split: bool, raw: bool);
	global define_header: function(a: string, h: string);
	global define_tag: function(a: string, tag: string);
	global buffer: function(a: string, value: bool);
	
	# This is dumb, but it helps avoid needing to duplicate code on the
	# printing side.
	const null_file: file = open_log_file("null");
}

function get_file_by_addr(a: string, ip: addr, force_log: bool): file
	{
	local i = logs[a];
	if ( !force_log && !addr_matches_hosts(ip, i$dh) )
		return LOG::null_file;

	if ( i$split && |local_nets| > 0 )
		{
		if ( is_local_addr(ip) )
			return i$files["split1-log"];
		else
			return i$files["split2-log"];
		}
	else
		{
		return i$files["combined-log"];
		}
	}
	
function get_file_by_id(a: string, id: conn_id, force_log: bool): file
	{
	local i = logs[a];
	if ( !force_log && !id_matches_directions(id, i$dh) )
		return LOG::null_file;

	if ( i$split && |local_nets| > 0 )
		{
		if ( is_local_addr(id$resp_h) )
			return i$files["split1-log"];
		else
			return i$files["split2-log"];
		}
	else
		{
		return i$files["combined-log"];
		}
	}
	
function print_log_by_addr(a: string, ip: addr, force_log: bool, tags: set[string], line: string): count
	{
	local log = get_file_by_addr(a, ip, force_log);
	print log, line;
	
	local lines_printed=0;
	if ( get_file_name(log) != "null.log" ) ++lines_printed;

	local i = logs[a];
	for ( tag in tags )
		{
		local prefix = cat(a,"-",tag,"-");  # http-ext-identified-files
		if ( prefix in logs )
			i = logs[prefix];
		
		if ( i$split && |local_nets| > 0 )
			{
			if ( is_local_addr(ip) )
				log = i$files["split1-log"];
			else
				log = i$files["split2-log"];
			}
		else
			{
			log = i$files["combined-log"];
			}
		print log, line;
		++lines_printed;
		}
	return lines_printed;
	}

function print_log_by_id(a: string, id: conn_id, force_log: bool, tags: set[string], line: string): count
	{
	local log = get_file_by_id(a, id, force_log);
	print log, line;
	
	local lines_printed=0;
	if ( get_file_name(log) != "null.log" ) ++lines_printed;
	
	local i = logs[a];
	for ( tag in tags )
		{
		local prefix = cat(a,"-",tag);  # http-ext-identified-files
		if ( prefix in logs )
			i = logs[prefix];
			
		if ( i$split && |local_nets| > 0 )
			{
			if ( is_local_addr(id$resp_h) )
				log = i$files["split1-log"];
			else
				log = i$files["split2-log"];
			}
		else
			{
			log = i$files["combined-log"];
			}
		print log, line;
		++lines_printed;
		}
	return lines_printed;
	}

function buffer(a: string, value: bool)
	{
	local i = logs[a];
	
	for ( f in i$files )
		{
		set_buf(i$files[f], value);
		}
	}

function open_log_files(a: string, tag: string)
	{
	local i = logs[a];
	
	if ( i$split && |local_nets| == 0 )
		print fmt("WARNING: Output log splitting requested for %s, but no networks defined in local_nets", a);
	
	local fname=a;
	if ( tag != "" )
		{
		fname = cat(a,"-",tag);
		if ( fname in logs )
			i = logs[fname];
		}

	if ( i$split && |local_nets| > 0 )
		{
		# Find if this log is determined by HOSTS or DIRECTIONS
		if ( i$dh in DIRECTIONS ) 
			{
			i$files["split1-log"] = open_log_file(cat(fname,"-inbound"));
			i$files["split2-log"] = open_log_file(cat(fname,"-outbound"));
			}
		else
			{
			i$files["split1-log"] = open_log_file(cat(fname,"-localhosts"));
			i$files["split2-log"] = open_log_file(cat(fname,"-remotehosts"));
			}
		}
	else
		{
		i$files["combined-log"] = open_log_file(fname);
		}
	}

function create_logs(a: string, d: Directions_and_Hosts, split: bool, raw: bool)
	{
	local x: table[string] of file = table();
	local y: set[string] = set();
	logs[a] = [$dh=d, $split=split, $raw_output=raw, $files=x, $tags=y];
	}
	
function define_header(a: string, h: string)
	{
	local i = logs[a];
	i$header = h;
	}
	
function define_tag(a: string, tag: string)
	{
	if ( a !in logs )
		{
		print fmt("WARNING: log type '%s' must be defined before adding tag '%s'.", a, tag);
		return;
		}
	# TODO: Validate this is being called during bro_init
	
	local i = logs[a];
	logs[cat(a,"-",tag)] = copy(i);
	add i$tags[tag];
	}
	
event file_opened(f: file) &priority=10
	{
	# Only do any of this for files opened locally.
	if ( is_remote_event() ) return;
	
	local filename = get_file_name(f);
	# TODO: make this not depend on the file extension being .log
	local log_type = gsub(filename, /(-(((in|out)bound)|(local|remote)hosts))?\.log$/, "");
	if ( log_type in logs )
		{
		local i = logs[log_type];
		if ( i$raw_output )
			enable_raw_output(f);
		if ( i$header != "" )
			print f, i$header;
		}
	else
		{
		# TODO: This needs to be handled.
		}
	}

# This is a hack.  The null file is used as /dev/null by all
# scripts using the logging framework.  The file needs to be
# closed so that nothing is ever written to it.
# TODO: change this when a better method for not printing
#       is created.
event bro_init()
	{
	close(null_file);
	}

# Open the appropriate log files.
event bro_init() &priority=-10
	{
	for ( lt in logs )
		{
		open_log_files(lt, "");
		# Open up all of the tagged log files if they exist.
		for ( tag in logs[lt]$tags )
			open_log_files(lt, tag);
		}
	}
