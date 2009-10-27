# For this script to work, you must define a local_mail table
# listing all of your known mail sending hosts.
# i.e.  const local_mail: set[subnet] = { 1.2.3.4/32 };

@ifdef ( local_mail )

@load conn-id
@load smtp

module SMTP;

type smtp_counter: record {
 rejects: count;
 total: count;
 connects: set[conn_id];
 rej_conns: set[conn_id];
};

export {
 # The idea for this is that if a host makes more than spam_threshold 
 # smtp connections per hour of which at least spam_percent of those are
 # rejected and the host is not a known mail sending host, then it's likely 
 # sending spam or viruses.
 #
 const spam_threshold = 300 &redef;
 const spam_percent = 30 &redef;

 # These are smtp status codes that are considered "rejected".
 const smtp_reject_codes: set[count] = {
   501, # Bad sender address syntax
   550, # Requested action not taken: mailbox unavailable
   551, # User not local; please try <forward-path>
   553, # Requested action not taken: mailbox name not allowed
   554, # Transaction failed
 };

 redef enum Notice += {
   SMTP_PossibleSpam, # Host sending mail *to* internal hosts is suspicious
   SMTP_PossibleInternalSpam, # Internal host seems to be spamming
   SMTP_StrangeRejectBehavior, # Local mail server is getting high numbers of rejects 
 };

 global smtp_status_comparison: table[addr] of smtp_counter &create_expire=1hr &redef;
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
		             msg: string, cont_resp: bool)
{
 if ( c$id$orig_h !in smtp_status_comparison ) 
 {
   local bar: set[conn_id];
   local blarg: set[conn_id];
   smtp_status_comparison[c$id$orig_h] = [$rejects=0, $total=0, $connects=bar, $rej_conns=blarg];
 }

 # Set the smtp_counter to the local var "foo"
 local foo = smtp_status_comparison[c$id$orig_h];

 if ( code in smtp_reject_codes &&
           c$id !in foo$rej_conns )
 {
   ++foo$rejects;
   local session = smtp_sessions[c$id];
   add foo$rej_conns[c$id];
 }

 if ( c$id !in foo$connects ) 
 {
   ++foo$total;
   add foo$connects[c$id];
 }

 local host = c$id$orig_h;
 if ( foo$total >= spam_threshold ) {
   local percent = (foo$rejects*100) / foo$total;
   if ( percent >= spam_percent ) {
     if ( host in local_mail )
       NOTICE([$note=SMTP_StrangeRejectBehavior, $msg=fmt("%s is rejecting a high percentage of mail", host), $sub=fmt("sent: %d rejected: %d percent", foo$total, percent), $conn=c]);
     else if ( is_local_addr(host) ) 
       NOTICE([$note=SMTP_PossibleInternalSpam, $msg=fmt("%s appears to be spamming", host), $sub=fmt("sent: %d rejected: %d percent", foo$total, percent), $conn=c]);
     else 
       NOTICE([$note=SMTP_PossibleSpam, $msg=fmt("%s appears to be spamming", host), $sub=fmt("sent: %d rejected: %d percent", foo$total, percent), $conn=c]);
   }
 }
}

@endif
