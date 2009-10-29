# For the SMTP_StrangeRejectBehavior notice to work, you must define a 
# local_mail table listing all of your known mail sending hosts.
# i.e.  const local_mail: set[subnet] = { 1.2.3.4/32 };
@load smtp

module SMTP;

type smtp_counter: record {
	rejects: count &default=0;
	total: count &default=0;
};

export {
	# The idea for this is that if a host makes more than reject_threshold 
	# smtp connections per hour of which at least reject_percent of those are
	# rejected and the host is not a known mail sending host, then it's likely 
	# sending spam or viruses.
	#
	const reject_threshold = 100 &redef;
	const reject_percent = 30 &redef;
	
	# These are smtp status codes that are considered "rejected".
	const bad_address_reject_codes: set[count] = {
		501, # Bad sender address syntax
		550, # Requested action not taken: mailbox unavailable
		551, # User not local; please try <forward-path>
		553, # Requested action not taken: mailbox name not allowed
		550, # Rejected
	};
	
	redef enum Notice += {
		SMTP_PossibleSpam, # Host sending mail *to* internal hosts is suspicious
		SMTP_StrangeRejectBehavior, # Local mail server is getting high numbers of rejects
	};
	
	# This variable keeps track of the number of rejected and accepted 
	# RCPT TO's a host has per hour.
	global reject_counter: table[addr] of smtp_counter &create_expire=1hr &redef;
	
	# Reduce the volume of notices raised by filtering out host that have 
	# already been detected as having too many rejected RCPT TOs.
	global notified_reject_spammers: set[addr] &create_expire=1hr &redef;
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool)
	{
	# If this is a continued response, it could be something like
	# the multiline rejections that gmail gives.  We only want to count
	# the first rejection in that case.
	if ( cont_resp ) return;
		
	if ( c$id$orig_h !in reject_counter )
		{
		local t: smtp_counter;
		reject_counter[c$id$orig_h] = t;
		}
	# Set the smtp_counter to the local var "sc"
	local sc = reject_counter[c$id$orig_h];
	
	# Whenever a "RCPT TO" is done, we add that to the total.
	if ( /^([rR][cC][pP][tT]|[mM][aA][iI][lL])/ in cmd )
		{
		++sc$total;
		if ( code in bad_address_reject_codes )
			++sc$rejects;
	
		if ( sc$total >= reject_threshold )
			{
			local percent = (sc$rejects*100) / sc$total;
			local host = c$id$orig_h;
			if ( percent >= reject_percent && 
				 host !in notified_reject_spammers )
				{
				local notice_type = SMTP_PossibleSpam;
@ifdef ( local_mail )
				if ( host in local_mail )
					notice_type = SMTP_StrangeRejectBehavior;
@endif
				NOTICE([$note=notice_type,
				        $msg=fmt("%s is having a large number of attempted recipients rejected", host),
				        $sub=fmt("attempted: %d rejected: %d percent",
				        sc$total, percent),
				        $conn=c]);
			
				add notified_reject_spammers[host];
				}
			}
		}
	}
