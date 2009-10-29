function numeric_id_string(id: conn_id): string
	{
	return fmt("%s:%d > %s:%d",
	           id$orig_h, id$orig_p,
	           id$resp_h, id$resp_p);
	}

function fmt_addr_set(input: addr_set): string
	{
	local output = "";
	local tmp = "";
	local len = length(input);
	local i = 1;

	for ( item in input )
		{
		tmp = fmt("%s", item);
		if ( len != i )
			tmp = fmt("%s ", tmp);
		i = i+1;
		output = fmt("%s%s", output, tmp);
		}
	return fmt("%s", output);
	}
	
function fmt_str_set(input: string_set, strip: pattern): string
	{
	local len = length(input);
	if ( len == 0 )
		return "{}";
	
	local output = "{";
	local tmp = "";
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

# Regular expressions for matching IP addresses in strings.
const ipv4_addr_regex = /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/;
const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/;
const ipv6_compressed_hex_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/;
const ipv6_hex4dec_regex = /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
const ipv6_compressed_hex4dec_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

# These are only commented out until this bug is fixed:
#    http://www.bro-ids.org/wiki/index.php/Known_Issues#Bug_with_OR-ing_together_pattern_variables
#const ipv6_addr_regex = ipv6_8hex_regex |
#                        ipv6_compressed_hex_regex |
#                        ipv6_hex4dec_regex |
#                        ipv6_compressed_hex4dec_regex;
#const ip_addr_regex = ipv4_addr_regex | ipv6_addr_regex;

const ipv6_addr_regex =     
    /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/ |
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/ | # IPv6 Compressed Hex
    /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/ | # 6Hex4Dec
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/; # CompressedHex4Dec

const ip_addr_regex = 
    /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/ |
    /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/ |
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/ | # IPv6 Compressed Hex
    /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/ | # 6Hex4Dec
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/; # CompressedHex4Dec

function is_valid_ip(ip_str: string): bool
	{
	if ( ip_str == ipv4_addr_regex )
		{
		local octets = split(ip_str, /\./);
		if ( |octets| != 4 )
			return F;
		
		local num=0;
		for ( i in octets )
			{
			num = to_count(octets[i]);
			if ( num < 0 || 255 < num )
				return F;
			}
		return T;
		}
	else if ( ip_str == ipv6_addr_regex )
		{
		# TODO: make this work correctly.
		return T;
		}
	return F;
	}

# This output a string_array of ip addresses extracted from a string.
# given: "this is 1.1.1.1 a test 2.2.2.2 string with ip addresses 3.3.3.3"
# outputs: { [1] = 1.1.1.1, [2] = 2.2.2.2, [3] = 3.3.3.3 }
function find_ip_addresses(input: string): string_array
	{
	local parts = split_all(input, ip_addr_regex);
	local output: string_array;
	
	for ( i in parts )
		{
		if ( i % 2 == 0 && is_valid_ip(parts[i]) )
			output[i/2] = parts[i];
		}
	return output;
	}


	
# Some enums for deciding what and when to log.
type Direction: enum { Inbound, Outbound, All };
type Hosts: enum { LocalHosts, RemoteHosts, AllHosts };

function orig_matches_direction(ip: addr, d: Direction): bool
	{
	if ( d == None ) return F;

	return ( d == All ||
	         (d == Outbound && is_local_addr(ip)) ||
	         (d == Inbound && !is_local_addr(ip)) );
	}
	
function resp_matches_direction(ip: addr, d: Direction): bool
	{
	if ( d == None ) return F;
	
	return ( d == All ||
	         (d == Inbound && is_local_addr(ip)) ||
	         (d == Outbound && !is_local_addr(ip)) );
	}

function conn_matches_direction(id: conn_id, d: Direction): bool
	{
	if ( d == None ) return F;
	
	return orig_matches_direction(id$orig_h, d);
	}
	
function resp_matches_hosts(ip: addr, d: Hosts): bool
	{
	if ( d == None ) return F;
	
	return ( d == AllHosts ||
	         (d == LocalHosts && is_local_addr(ip)) ||
	         (d == RemoteHosts && !is_local_addr(ip)) );
	}
