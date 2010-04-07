@load listen-clear

type snort_alert_data: record {
	ts: time;                     # timestamp
	sig_generator: count;         # which part of snort generated the alert?
	sig_id: count;                # sig id for this generator
	sig_rev: count;               # sig revision for this id
	event_classification: string; # event classification
	event_priority: count;        # event priority
	event_id: count;              # event ID
	event_reference: count;       # reference to other events that have gone off,
};

type packet_id: record {
	src_ip: addr;
	src_p: port;
	dst_ip: addr;
	dst_p: port;
};

# This is the event that Snort instances will send if they're configured with
# the bro_alert output plugin.
global snort_alert: event(id: packet_id, sad: snort_alert_data, msg: string, packet: string);

module Snort;

redef Remote::destinations += {
	["snort"] = [$host=127.0.0.1, $connect=F, $sync=F, $class="snort", $events=/snort_alert/ ]
};

export {
	# pid2cid can convert a Snort packet_id value to a conn_id value in the
	# case that you might need to index into an existing data structure 
	# elsewhere within Bro.
	global pid2cid: function(p: packet_id): conn_id;
}


function pid2cid(p: packet_id): conn_id
	{
	return [$orig_h=p$src_ip, $orig_p=p$src_p, $resp_h=p$dst_ip, $resp_p=p$dst_p];
	}

event snort_alert(id: packet_id, sad: snort_alert_data, msg: string, packet: string)
	{
	if ( /Corporate/ in sad$event_classification )
		return;
	
	print pid2cid(id);
	print fmt("%.6f class:%s pri:%d ev_id:%d ev_ref:%d sig_gen:%d sig_id:%d sig_rev:%d msg:%s", sad$ts, sad$event_classification, sad$event_priority, sad$event_id, sad$event_reference, sad$sig_generator, sad$sig_id, sad$sig_rev, msg);
	print packet;
	}

event bro_init() &priority=-10
	{
	print "ready.";
	}

event remote_connection_established(p: event_peer)
	{
	print "remote connection established";
	}

event remote_connection_closed(p: event_peer)
	{
	print "remote connection closed";
	}
