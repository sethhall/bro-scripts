@load listen-clear

type barnyard_alert_data: record {
	sensor_id: count;           # sensor that originated this event
	ts: time;                   # timestamp
	signature_id: count;        # sig id for this generator
	generator_id: count;        # which generator generated the alert?
	signature_revision: count;  # sig revision for this id
	classification_id: count;   # event classification
	classification: string;
	priority_id: count;         # event priority
	event_id: count;            # event ID
	#references: set[string] &optional;   # reference to other events that have gone off,
};

type packet_id: record {
	src_ip: addr;
	src_p: port;
	dst_ip: addr;
	dst_p: port;
};

# This is the event that Barnyard2 instances will send if they're 
# configured with the bro_alert output plugin.
global barnyard_alert: event(id: packet_id, sad: barnyard_alert_data, msg: string, data: string);

redef Remote::destinations += {
	["barnyard"] = [$host=127.0.0.1, $connect=F, $sync=F, $class="barnyard", $events=/barnyard_alert/ ]
};


module Barnyard;

export {
	# pid2cid can convert a Barnyard packet_id value to a conn_id value in the
	# case that you might need to index into an existing data structure 
	# elsewhere within Bro.
	global pid2cid: function(p: packet_id): conn_id;
	
	global log_file = open_log_file("barnyard");
}

function pid2cid(p: packet_id): conn_id
	{
	return [$orig_h=p$src_ip, $orig_p=p$src_p, $resp_h=p$dst_ip, $resp_p=p$dst_p];
	}

event barnyard_alert(id: packet_id, sad: barnyard_alert_data, msg: string, data: string)
	{
	local proto_connection_string: string;
	if ( id$src_p == 0/tcp )
		proto_connection_string = fmt("{PROTO:255} %s -> %s", id$src_ip, id$dst_ip);
	else
		proto_connection_string = fmt("{%s} %s:%d -> %s:%d", 
		                              to_upper(fmt("%s", get_port_transport_proto(id$dst_p))),
		                              id$src_ip, id$src_p, id$dst_ip, id$dst_p);
	
	print log_file, fmt("%.6f [**] [%d:%d:%d] %s [**] [Classification: %s] [Priority: %d] %s", 
	                     sad$ts,
	                     sad$generator_id,
	                     sad$signature_id,
	                     sad$signature_revision,
	                     msg, 
	                     sad$classification, 
	                     sad$priority_id, 
	                     proto_connection_string);
	}
	