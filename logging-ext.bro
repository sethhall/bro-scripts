module LOG;

export {
	# The record type to store logging information.
	type log_info: record {
		dh:           Directions_and_Hosts &default=All;
		split:        bool                 &default=F;
		raw_output:   bool                 &default=F;
		header:       string               &default="";
		combined_log: file                 &optional;
		split1_log:   file                 &optional;
		split2_log:   file                 &optional;
	};
	
	# Where the data for knowing how to log is stored.
	const logs: table[string] of log_info &redef;

	# Utility functions
	global get_file_by_addr: function(a: string, ip: addr, force_log: bool): file;
	global get_file_by_id: function(a: string, id: conn_id, force_log: bool): file;
	global open_log_files: function(a: string);
	global create_logs: function(a: string, d: Directions_and_Hosts, split: bool, raw: bool);
	global define_header: function(a: string, h: string);
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

	if ( i$split )
		{
		if ( is_local_addr(ip) )
			return i$split1_log;
		else
			return i$split2_log;
		}
	else
		{
		return i$combined_log;
		}
	}
	
function get_file_by_id(a: string, id: conn_id, force_log: bool): file
	{
	local i = logs[a];
	if ( !force_log && !id_matches_directions(id, i$dh) )
		return LOG::null_file;

	if ( i$split )
		{
		if ( is_local_addr(id$resp_h) )
			return i$split1_log;
		else
			return i$split2_log;
		}
	else
		{
		return i$combined_log;
		}
	}


function buffer(a: string, value: bool)
	{
	local i = logs[a];
	
	if ( i$split )
		{
		set_buf(i$split1_log, value);
		set_buf(i$split2_log, value);
		}
	else
		{
		set_buf(i$combined_log, value);
		}
	}

function open_log_files(a: string)
	{
	local i = logs[a];
	
	if ( i$split )
		{
		# Find if this log is determined by HOSTS or DIRECTIONS
		if ( i$dh in DIRECTIONS ) 
			{
			i$split1_log = open_log_file(cat(a,"-inbound"));
			i$split2_log = open_log_file(cat(a,"-outbound"));
			}
		else
			{
			i$split1_log = open_log_file(cat(a,"-localhosts"));
			i$split2_log = open_log_file(cat(a,"-remotehosts"));
			}
		}
	else
		{
		i$combined_log = open_log_file(a);
		}
	}

function create_logs(a: string, d: Directions_and_Hosts, split: bool, raw: bool)
	{
	logs[a] = [$dh=d, $split=split, $raw_output=raw];
	}
	
function define_header(a: string, h: string)
	{
	local i = logs[a];
	i$header = h;
	}
	
event file_opened(f: file) &priority=10
	{
	local filename = get_file_name(f);
	# TODO: make this not depend on the file extension being .log
	local log_type = gsub(filename, /(-(((in|out)bound)|(local|remote)hosts))?\.log$/, "");
	if ( log_type in logs )
		{
		local i = logs[log_type];
		if ( i$raw_output )
			enable_raw_output(f);
		if ( !is_remote_event() && i$header != "" )
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
		open_log_files(lt);
	}
