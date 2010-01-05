
@load notice

module SSN;

export {
	# You must redef this variable with a normalized list of SSNs.
	#   If you would like or require trivial obfuscation, you can set 
	#   the use_md5_hashed_ssns variable to T and put md5 hashed SSNs
	#   into the list.
	# Example for redefining this variable... (huge sets are handled easily)
	#   redef SSN::SSN_list = {"264439985", "351669087"};
	const SSN_list: set[string] &redef;

	# As commented above, set this to T if you are using hashed SSNs in your 
	# SSN_list variable.
	const use_md5_hashed_ssns = F &redef;
	
	# If you think that there could be SSNs passed around without separators
	# (just 9 digit integers), then set this to T.  
	const check_with_no_separator = F &redef;

	const ssn_log = open_log_file("ssn-exposure") &raw_output &redef;

	redef enum Notice += {
	  SSN_Exposure,
	  SSN_MassExposure,
	};

	# The threshold of SSNs that you want to qualify as a mass disclosure.
	# This allows you to only alarm on more significant disclosures 
	#  (instead of people sending their own SSN).
	# NOT CURRENTLY WORKING!
	const mass_exposure_num = 5 &redef;

	# Put the following line in your local config before @load-ing this script
	# if you'd like to use the signature based technique.
	#const use_ssn_sigs = T;
}

# This variable is for tracking the valid SSNs detected per-connection.
#   This should catch SSN leakage over email.
global ssn_conn_tracker: table[conn_id] of set[string] &create_expire=5mins &default=function(id:conn_id):string_set { return set(); };

# This variable tracks the valid SSNs detected per-service.
#   The idea is that this would catch SSN leakage through an SQL injection attack.
global ssn_serv_tracker: table[addr, port] of set[string] &create_expire=5mins &default=function(a:addr, p:port):string_set { return set(); };

@ifdef (use_ssn_sigs)
@load signatures
redef signature_files += "ssn.sig";
redef signature_actions += { ["ssn-match"] = SIG_IGNORE };
@else 
# Conn is needed because of a small dependency between smtp.bro and conn.bro
@load conn
@load smtp
@load http-reply
@endif

#redef notice_action_filters += { [SSN::SSN_Exposure] = ignore_notice };

const ssn_regex = /[^0-9\/]\0?[0-6](\0?[0-9]){2}\0?[ \-]?(\0?[0-9]){2}\0?[ \-]?(\0?[0-9]){4}(\0?[[:blank:]\r\n<\"\'])/;

# This function is used for validating and notifying about SSNs in a string.
function check_ssns(c: connection, data: string): bool
	{
	local ssnps = find_all(data, ssn_regex);
	
	for ( ssnp in ssnps )
		{
		# Make sure the number has either 2 hyphens, 2 spaces, or no separators.
		if ( /[\x000-9]{3}\x00?-[\x000-9]{2}\x00?-[\x000-9]{4}/ in ssnp ||
		     /[\x000-9]{3}\x00?[[:blank:]][\x000-9]{2}\x00?[[:blank:]][\x000-9]{4}/ in ssnp ||
		     (check_with_no_separator && /[\x000-9]{9}/ in ssnp) )
			{
			# Remove all non-numerics
			local clean_ssnp = gsub(ssnp, /[^0-9]/, "");
			# Strip off any leading chars
			local ssn = sub_bytes(clean_ssnp, byte_len(clean_ssnp)-8, 9);
			
			#print fmt("Checking on -%s-", ssn);
			local hash_ssn: string;
			if ( use_md5_hashed_ssns )
				hash_ssn = md5_hash(ssn);
			else
				hash_ssn = ssn;
				
			if ( hash_ssn in SSN_list )
				{
				local id = c$id;
				#print fmt("  %s - Found it! (%s)", ssn, md5_hash(ssn));
				add ssn_conn_tracker[id][ssn];
				if ( |ssn_conn_tracker[id]| >= mass_exposure_num )
					{
					NOTICE([$note=SSN_MassExposure,
					        $conn=c,
					        $msg=fmt("More than %i SSNs disclosed in one connection.", mass_exposure_num)]);
					}
				else
					{
					NOTICE([$note=SSN_Exposure,
					        $conn=c,
					        $msg=fmt("Contents of disclosed ssn session: %s", data),
					        $sub=hash_ssn]);
					}
			
				print ssn_log, cat_sep("\t", "\\N", network_time(),
				                       id$orig_h, fmt("%d", id$orig_p), 
				                       id$resp_h, fmt("%d", id$resp_p), 
				                       ssn, data);
				return T;
				}
			}
		}
		return F;
	}

# This is used if the mime event parsing technique is used.
#   This seems to be the better technique if HTTP and SMTP are where
#   the SSN leakage problems are in your environment (especially if you 
#   are able to use DPD).
event smtp_data(c: connection, is_orig: bool, data: string)
	{
	# Only looking at outbound SMTP.
	if ( is_orig && is_local_addr(c$id$orig_h) && 
	     c$start_time > network_time()-10secs && ssn_regex in data )
		check_ssns(c, data);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	# We're looking for outbound POST data and outbound HTTP data contents.
	if ( ((is_local_addr(c$id$resp_h) && !is_orig) || (is_local_addr(c$id$orig_h) && is_orig)) &&
	     c$start_time > network_time()-10secs && ssn_regex in data )
		check_ssns(c, data);
	}
	
# This event is broken in Robin's branch currently
#event mime_all_data(c: connection, length: count, data: string)
#	{
#	# Only check the regex for connections younger than 10 seconds.
#	#   This helps avoid load during large and/or long connections.
#	if ( c$start_time > network_time()-10secs && ssn_regex in data )
#		check_ssns(c, data);
#	}

# This is used if the signature based technique is in use
function validate_ssn_match(state: signature_state, data: string): bool
	{
	# TODO: Don't handle HTTP data this way.  Should return F if this is
	#       an http/smtp session and handle the relevant *_data events.
	if ( /^GET/ in data )
		return F;

	return check_ssns(state$conn, data);
	}