@load http-ext-identified-files

module HTTP;

# This function is used when expiring data from building_md5_sums
function expire_md5_sum(the_set: set[conn_id], index: conn_id): interval
	{
	# The data structure behind the md5_hash_* functions needs to be released.
	md5_hash_finish(index);
	return 0secs; # go ahead and delete this data now
	}

export {
	redef enum Notice += {
		# Notice type when we encounter an md5sum in Team Cymru's Malware
		# Hash Registry.  http://www.team-cymru.org/Services/MHR/
		HTTP_MHR_Malware,

		# Notice type when locally defined md5sum's are encountered.
		HTTP_MD5,
	};
	
	# Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ &redef; # *NIX executable binary
	
	# MD5 sums that are "interesting" for your local network.
	# The index is the MD5 sum and the yield value is used as the $msg value
	# for notices so that you can filter in your local notice policy.
	const interesting_md5: table[string] of string &redef;
	
	# This variable is for keeping track of the files that are currently
	# having hashes built.
	global building_md5_sums: set[conn_id] &write_expire=1min
	                                       &expire_func=expire_md5_sum
	                                       &redef;
}

# Once a file that we're interested has begun downloading, initialize
# an MD5 hash.
event file_transferred(c: connection, prefix: string, descr: string, mime_type: string)
	{
	if ( generate_md5 in mime_type && 
		 c$id in conn_info &&
		 c$id !in building_md5_sums )
		{
		add building_md5_sums[c$id];
		md5_hash_init(c$id);
		}
	}

# As the file downloads, continue building the hash.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( !is_orig && c$id in building_md5_sums )
		md5_hash_update(c$id, data);
	}
	
# When the file finishes downloading, finish the hash, check for the hash
# in the MHR, and raise a notice if the hash is there.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=10
	{
	if ( is_orig ) return;
	
	if ( c$id in building_md5_sums )
		{
		local si = conn_info[c$id];
		
		si$md5 = md5_hash_finish(c$id);
		
		if ( si$md5 in interesting_md5 )
			{
			NOTICE([$note=HTTP_MD5, $conn=c, $method=si$method, $URL=si$url,
			        $msg=interesting_md5[si$md5],
			        $sub=si$md5]);
			}
		
		local hash_domain = fmt("%s.malware.hash.cymru.com", si$md5);
		when ( local addrs = lookup_hostname(hash_domain) )
			{
			if ( 127.0.0.2 in addrs )
				{
				local message = fmt("%s %s %s", c$id$orig_h, si$md5, si$url);
				NOTICE([$note=HTTP_MHR_Malware, $msg=message, $conn=c,
				        $method=si$method, $URL=si$url]);
				}
			}
		delete building_md5_sums[c$id];
		}
	}