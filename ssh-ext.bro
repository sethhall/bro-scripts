# Copyright 2008 Seth Hall <hall.692@osu.edu>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that: (1) source code distributions
# retain the above copyright notice and this paragraph in its entirety, (2)
# distributions including binary code include the above copyright notice and
# this paragraph in its entirety in the documentation or other materials
# provided with the distribution, and (3) all advertising materials mentioning
# features or use of this software display the following acknowledgement:
# ``This product includes software developed by the University of California,
# Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
# the University nor the names of its contributors may be used to endorse
# or promote products derived from this software without specific prior
# written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
@load functions-ext

module SSH;

export {
	const login_log = open_log_file("ssh-logins") &redef;
	
	const password_guesses_limit = 30 &redef;
	const authentication_data_size = 5500 &redef;
	const guessing_timeout = 30 mins;
	
	# Keeps count of how many rejections a host has had
	global password_rejections: table[addr] of count &default=0 &write_expire=guessing_timeout;
	# Keeps track of hosts identified as guessing passwords
	global password_guessers: set[addr] &write_expire=guessing_timeout+1hr;
	
	# The set of countries for which you'd like to throw notices
	#   require Bro compiled with libGeoIP support
	const watched_countries: set[string] = {"RO"} &redef;
	
	# This is a table with orig host as the key, and resp host as the value.
	const ignore_guessers: table[subnet] of subnet &redef;
	
	redef enum Notice += {
	  SSH_Login,
	  SSH_PasswordGuessing,
	  SSH_LoginByPasswordGuesser,
	};
} 

global ssh_conns:set[conn_id];
global ssh_watching:bool = F;

# Don't stop processing SSH connections in the default ssh policy script
redef skip_processing_after_handshake = F;

# Examples for how to handle notices from this script.
#     (define these in a local script)...
#redef notice_policy += {
#	# Send email if a successful ssh login happens from or to a watched country
#	[$pred(n: notice_info) = 
#		{ return (n$note == SSH::SSH_Login && n$sub in watched_countries); },
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

event check_ssh_connection(c: connection)
	{
	# make sure the server has sent back more than 50 bytes to filter out
	# hosts that are just port scanning.
	if (c$resp$size < 50)
		return;
	
	local message = "";
	if ( c$resp$size < authentication_data_size ) 
		{
		# presumed failure

		if ( !(c$id$orig_h in ignore_guessers &&
		       c$id$resp_h in ignore_guessers[c$id$orig_h]) )
			password_rejections[c$id$orig_h] += 1;

		message = fmt("failed ssh login %s (saw %d bytes)",
		              numeric_id_string(c$id), c$resp$size);
		print login_log, fmt("%.6f %s", network_time(), message);

		if ( password_rejections[c$id$orig_h] > password_guesses_limit && 
		     c$id$orig_h !in password_guessers )
			{
			add password_guessers[c$id$orig_h];
			NOTICE([$note=SSH_PasswordGuessing,
			        $conn=c,
			        $msg=fmt("ssh password guessing by %s", c$id$orig_h)]);
			}

		} 
	# TODO: This is to work around a quasi-bug in Bro which occasionally 
	#       causes the byte count to be oversized.
	else if (c$resp$size < 20000000) 
		{ 
		# presumed successful login

		if ( password_rejections[c$id$orig_h] > password_guesses_limit &&
		     c$id$orig_h !in password_guessers)
			{
			add password_guessers[c$id$orig_h];
			NOTICE([$note=SSH_LoginByPasswordGuesser,
			        $conn=c,
			        $n=password_rejections[c$id$orig_h],
			        $msg=fmt("ssh successful login by password guesser %s attempted logging in %d times", 
			                 numeric_id_string(c$id), password_rejections[c$id$orig_h])]);
			}

			local direction = is_local_addr(c$id$orig_h) ? "to" : "from";
			local location = (direction == "to") ? lookup_location(c$id$resp_h) : lookup_location(c$id$orig_h);
			message = fmt("ssh login %s %s \"%s\" \"%s\" %f %f %s (triggered with %d bytes)",
			              direction, location$country_code, location$region, location$city,
			              location$latitude, location$longitude,
			              numeric_id_string(c$id), c$resp$size);
			NOTICE([$note=SSH_Login,
			        $conn=c,
			        $msg=message,
			        $sub=location$country_code]);
			print login_log, fmt("%.6f %s", network_time(), message);
		}
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in ssh_conns )
		return;
	
	delete ssh_conns[c$id];
	event check_ssh_connection(c);
	}

event ssh_watcher()
	{
	for ( id in ssh_conns )
		{
		# don't go any further if this connection is gone already
		if ( !connection_exists(id) )
			next;

		local c = lookup_connection(id);
		event check_ssh_connection(c);

		# Stop watching this connection, we don't care about it anymore.
		skip_further_processing(c$id);
		set_record_packets(c$id, F);
		delete ssh_conns[id];
		}

	if ( |ssh_conns| > 0 )
		schedule +2mins { ssh_watcher() };
	else
		ssh_watching = F;
	}

event protocol_confirmation(c: connection, atype: count, aid: count)
	{
	if ( atype == ANALYZER_SSH )
		{
		add ssh_conns[c$id];
		if (!ssh_watching)
			{
			ssh_watching = T;
			# TODO: change this to have a scheduled task per-connection
			schedule +2mins { ssh_watcher() }; 
			}
		}
	}
