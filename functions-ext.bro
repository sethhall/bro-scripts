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

function numeric_id_string(id: conn_id): string
	{
	return fmt("%s:%d > %s:%d",
	           id$orig_h, id$orig_p,
	           id$resp_h, id$resp_p);
	}

function fmt_str_set(input: string_set, strip: pattern): string
	{
	local output = "{";
	local tmp = "";
	local len = length(input);
	local i = 1;
	
	for ( item in input )
		{
		tmp = fmt("%s", gsub(item, strip, ""));
		if ( len != i )
			tmp = fmt("%s, ", tmp);
		i = i+1;
		output = fmt("%s%s", output, tmp);
		}
	return fmt("%s}", output);
	}
	
const ip_addr_regex = /^[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}$/;
# TODO: match ipv6 addresses also
function is_valid_ip(ip_str: string): bool
	{
	return (ip_str == ip_addr_regex);
	}

# This enum and the associated functions help to build 
type Direction: enum { inbound, outbound, bidirectional };
function orig_h_matches_direction(ip: addr, d: Direction): bool
	{
	return ( (d == outbound && is_local_addr(ip)) ||
	         (d == inbound && !is_local_addr(ip)) ||
	         d == bidirectional );
	}
function conn_matches_direction(id: conn_id, d: Direction): bool
	{
	return orig_h_matches_direction(id$orig_h, d);
	}
