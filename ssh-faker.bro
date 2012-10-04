##! Watch for non-local hosts connecting to SSH servers on port 22/tcp 
##! and not speaking SSH.

redef enum Notice::Type += {
	## Indicates that a remote client has spoken something other than 
	## SSH on port 22.
	Remote_SSH_Faker
};

event protocol_violation(c: connection, atype: count, aid: count, reason: string)
	{
	if ( analyzer_name(atype) == "SSH" && 
	     !Site::is_local_addr(c$id$orig_h) && 
	     c$id$resp_p == 22/tcp )
		{
		NOTICE([$note=Remote_SSH_Faker,
		        $src=c$id$orig_h,
		        $msg=fmt("The remote host %s didn't speak SSH correctly", c$id$orig_h),
		        $identifier=cat(c$id$orig_h)]); 
		}
	}

