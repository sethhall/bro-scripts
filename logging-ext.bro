module LOG;

export {
	# The record type to store logging information.
	type log_info: record {
		direction:    Direction &default=All;
		split:        bool      &default=F;
		raw_output:   bool      &default=F;
		log:          file      &raw_output &optional;
		outbound_log: file      &raw_output &optional;
		inbound_log:  file      &raw_output &optional;
	};
	
	# Where the data for knowing how to log is stored.
	const logs: table[string] of log_info &redef;

	# Utility functions
	global choose: function(a: string, server: addr): file;
	global open_log_files: function(a: string);
	global create_logs: function(a: string, d: Direction, split: bool, raw: bool);

	# This is dumb, but it helps avoid needing to duplicate code on the
	# printing side.
	const null_file: file = open_log_file("null");
}


function choose(a: string, server: addr): file
	{
	local i = logs[a];
	if ( ! resp_matches_direction(server, i$direction) )
		return LOG::null_file;
		
	if ( i$split )
		{
		if ( is_local_addr(server) )
			return i$inbound_log;
		else
			return i$outbound_log;
		}
	else
		{
		return i$log;
		}
	}

function open_log_files(a: string)
	{
	local i = logs[a];
	if ( i$direction == None ) return;
	
	if ( i$split )
		{
		i$inbound_log = open_log_file(cat(a,"-inbound"));
		i$outbound_log = open_log_file(cat(a,"-outbound"));
		if ( i$raw_output )
			{
			enable_raw_output(i$inbound_log);
			enable_raw_output(i$outbound_log);
			}
		}
	else
		{
		i$log = open_log_file(a);
		if ( i$raw_output )
			{
			enable_raw_output(i$log);
			}
		}
	}

function create_logs(a: string, d: Direction, split: bool, raw: bool)
	{
	logs[a] = [$direction=d, $split=split, $raw_output=raw];
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

event bro_init() &priority=-10
	{
	local d = set(Inbound,Outbound,All,None);
	for ( lt in logs )
		{
		# This doesn't work for some reason.
		#if ( logs[lt]$direction !in d )
		#	print fmt("Invalid direction chosen for %s", lt);
		
		# Open the appropriate log files.
		open_log_files(lt);
		}
	}
