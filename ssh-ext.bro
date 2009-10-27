@load global-ext
@load ssh
@load notice
	
module SSH;

export {
	const ssh_ext_log = open_log_file("ssh-ext") &raw_output;
	
	const password_guesses_limit = 30 &redef;
	const authentication_data_size = 5500 &redef;
	const guessing_timeout = 30 mins;
	
	# Keeps count of how many rejections a host has had
	global password_rejections: table[addr] of count &default=0 &write_expire=guessing_timeout;
	# Keeps track of hosts identified as guessing passwords
	global password_guessers: set[addr] &read_expire=guessing_timeout+1hr;
	
	type ssh_versions: record {
		client: string &default="";
		server: string &default="";
	};
	
	# Only monitor SSH connections for up to 15 minutes
	global active_ssh_conns: table[conn_id] of ssh_versions &create_expire=15mins;
	
	# If you want to lookup and log geoip data in the event of a failed login.
	const log_geodata_on_failure = F &redef;
	
	# The set of countries for which you'd like to throw notices upon successful login
	#   requires Bro compiled with libGeoIP support
	const watched_countries: set[string] = {"RO"} &redef;
	
	# Strange/bad host names to originate successful SSH logins
	const strange_hostnames =
			/^d?ns[0-9]*\./ |
			/^smtp[0-9]*\./ |
			/^mail[0-9]*\./ |
			/^pop[0-9]*\./  |
			/^imap[0-9]*\./ |
			/^www[0-9]*\./  |
			/^ftp[0-9]*\./  &redef;

	# This is a table with orig subnet as the key, and subnet as the value.
	const ignore_guessers: table[subnet] of subnet &redef;
	
	redef enum Notice += {
		SSH_Login,
		SSH_PasswordGuessing,
		SSH_LoginByPasswordGuesser,
		SSH_Login_From_Strange_Hostname,
		SSH_Bytecount_Inconsistency,
	};
} 

# Examples for how to handle notices from this script.
#     (define these in a local script)...
#redef notice_policy += {
#	# Send email if a successful ssh login happens from or to a watched country
#	[$pred(n: notice_info) = 
#		{ return (n$note == SSH::SSH_Login && n$sub in SSH::watched_countries); },
#	 $result = NOTICE_EMAIL],
#
#	# Send email if a password guesser logs in successfully anywhere
#	# To avoid false positives, setting the lower bound for notification to 50 bad password attempts.
#	[$pred(n: notice_info) = 
#		{ return (n$note == SSH::SSH_LoginByPasswordGuesser && n$n > 50); },
#	 $result = NOTICE_EMAIL],
#
#	# Send email if a local host is password guessing.
#	[$pred(n: notice_info) = 
#		{ return (n$note == SSH::SSH_PasswordGuessing && 
#		          is_local_addr(n$conn$id$orig_h)); },
#	 $result = NOTICE_EMAIL], 
#};

# Don't stop processing SSH connections in the default ssh policy script
redef skip_processing_after_handshake = F;

event check_ssh_connection(c: connection, done: bool)
	{
	# If this is no longer a known SSH connection, just return.
	if ( c$id !in active_ssh_conns )
		return;
	
	# If this is still a live connection and the byte count has not
	# crossed the threshold, just return and let the resheduled check happen later.
	if ( !done && c$resp$size < authentication_data_size )
		return;

	# Make sure the server has sent back more than 50 bytes to filter out
	# hosts that are just port scanning.  Nothing is ever logged if the server
	# doesn't send back at least 50 bytes.
	if (c$resp$size < 50)
		return;
	
	local versions = active_ssh_conns[c$id];
	local status = "failure";
	local direction = is_local_addr(c$id$orig_h) ? "to" : "from";
	local location: geo_location;
	# Need to give these values defaults in bro.init.
	location$country_code=""; location$region=""; location$city=""; location$latitude=0.0; location$longitude=0.0;
	
	if ( done && c$resp$size < authentication_data_size ) 
		{
		# presumed failure

		# Track the number of rejections
		if ( !(c$id$orig_h in ignore_guessers &&
		       c$id$resp_h in ignore_guessers[c$id$orig_h]) )
			password_rejections[c$id$orig_h] += 1;

		if ( password_rejections[c$id$orig_h] > password_guesses_limit && 
		     c$id$orig_h !in password_guessers )
			{
			add password_guessers[c$id$orig_h];
			NOTICE([$note=SSH_PasswordGuessing,
			        $conn=c,
			        $msg=fmt("SSH password guessing by %s", c$id$orig_h),
			        $sub=fmt("%d failed logins", password_rejections[c$id$orig_h]),
			        $n=password_rejections[c$id$orig_h]]);
			}
		} 
	# TODO: This is to work around a quasi-bug in Bro which occasionally 
	#       causes the byte count to be oversized.
	else if (c$resp$size < 20000000) 
		{ 
		# presumed successful login
		status = "success";

		if ( password_rejections[c$id$orig_h] > password_guesses_limit &&
		     c$id$orig_h !in password_guessers)
			{
			add password_guessers[c$id$orig_h];
			NOTICE([$note=SSH_LoginByPasswordGuesser,
			        $conn=c,
			        $n=password_rejections[c$id$orig_h],
			        $msg=fmt("Successful SSH login by password guesser %s", c$id$orig_h),
			        $sub=fmt("%d failed logins", password_rejections[c$id$orig_h])]);
			}

		local message = fmt("SSH login %s %s \"%s\" \"%s\" %f %f %s (triggered with %d bytes)",
		              direction, location$country_code, location$region, location$city,
		              location$latitude, location$longitude,
		              numeric_id_string(c$id), c$resp$size);
		# TODO: rewrite the message once a location variable can be put in notices
		NOTICE([$note=SSH_Login,
		        $conn=c,
		        $msg=message,
		        $sub=location$country_code]);
		
		# Check to see if this login came from a weird hostname (nameserver, mail server, etc.)
		when( local hostname = lookup_addr(c$id$orig_h) )
			{
			if ( strange_hostnames in hostname )
				{
				NOTICE([$note=SSH_Login_From_Strange_Hostname,
				        $conn=c,
				        $msg=fmt("Strange login from %s", hostname),
				        $sub=hostname]);
				}
			}
		}
	else if (c$resp$size >= 20000000) 
		{
		NOTICE([$note=SSH_Bytecount_Inconsistency,
		        $conn=c,
		        $msg="During byte counting in extended SSH analysis, an overly large value was seen.",
		        $sub=fmt("%d",c$resp$size)]);
		}
		
	if ( (log_geodata_on_failure && status == "failure") ||
	     status == "success" )
		{
		location = (direction == "to") ? lookup_location(c$id$resp_h) : lookup_location(c$id$orig_h);
		}
		
	print ssh_ext_log, cat_sep("\t", "\\N", c$start_time,
				c$id$orig_h, fmt("%d", c$id$orig_p),
				c$id$resp_h, fmt("%d", c$id$resp_p),
				status, direction, 
				location$country_code, location$region,
				versions$client, versions$server,
				c$resp$size);

	delete active_ssh_conns[c$id];
	# Stop watching this connection, we don't care about it anymore.
	skip_further_processing(c$id);
	set_record_packets(c$id, F);
	}

event connection_state_remove(c: connection)
	{
	event check_ssh_connection(c, T);
	}

event ssh_watcher(c: connection)
	{
	local id = c$id;
	# don't go any further if this connection is gone already!
	if ( !connection_exists(id) )
		{
		delete active_ssh_conns[id];
		return;
		}

	event check_ssh_connection(c, F);
	if ( c$id in active_ssh_conns )
		schedule +2mins { ssh_watcher(c) };
	}
	
event ssh_client_version(c: connection, version: string)
	{
	if ( c$id in active_ssh_conns )
		active_ssh_conns[c$id]$client = version;
	}

event ssh_server_version(c: connection, version: string)
	{
	if ( c$id in active_ssh_conns )
		active_ssh_conns[c$id]$server = version;
	}

event protocol_confirmation(c: connection, atype: count, aid: count)
	{
	if ( atype == ANALYZER_SSH )
		{
		local tmp: ssh_versions;
		active_ssh_conns[c$id]=tmp;
		schedule +2mins { ssh_watcher(c) }; 
		}
	}
