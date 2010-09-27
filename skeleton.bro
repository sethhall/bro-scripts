# TODO:
#   * Figure out a style for Sphinx-type documentation.
# 

# Load all of the other scripts this script depends on.  Try to be careful to
# not load more than necessary, but it's good practice to be sure that all 
# dependencies are loaded so that users only need to load this single script.
@load global-ext

# Define your namespace where all of your locally defined functions and
# variables will reside.
module Skeleton;

# Define any notices that this script raises.
redef enum Notice += { 
	Skeleton_Bad_Thing,
	Skeleton_Another_Bad_Thing,
	Skeleton_Just_An_Interesting_Thing,
};

# The export section contains the external interface for customizing your 
# script and accessing useful internal state.  Consts defined here should 
# be used for changing the behavior of the script and *MUST* have the &redef
# attribute.  Globals should be used for storing information which 
# is used by this script, but may be useful to another script at runtime.
export {
	#============================#
	# Configuration variables    #
	#============================#
	# Selectively enable or disable what is logged.
	# If the data being logged are attributes of hosts/IP addresses, then
	# the choices are: LocalHosts, RemoteHosts, Enabled, Disabled.
	# Alternately you can use: Inbound, Outbound, Enabled, and Disabled if
	# the scripts logs attributes of connections.
	# The default for this option should be what generally makes the most
	# sense from an operational standpoint.  E.g. using a default of 
	# LocalHosts for logging HTTP User-Agents as it's likely that data is more
	# useful operationally.
	const logging = LocalHosts &redef;
	
	# Include this option if the log file can be split by local/remote 
	# or inbound/outbound.
	# The default for this variable should always be F.
	const split_log_file = F &redef;
	
	# This is an example of defining a set to exclude false positives.  There 
	# could be addresses which are known to do an activity that is generally 
	# benign but causes this script to generate an unwanted notice.
	# It would likely be used within the script like:
	#   if ( id$orig_h in ignore_hosts) return;
	const ignore_hosts: set[addr] &redef
	
	#============================#
	# Exported state information #
	#============================#
	# These are examples of defining data that could be useful to other scripts.
	# This will likely change when the Intelligence sources framework is available.
	global bad_addrs: set[addr] &create_expire=1day;
	global users_at_ip_addrs: table[addr] of string &create_expire=3hours;

	#============================#
	# Exported utility functions #
	#============================#
	# These are functions that you want to be able to use from other modules.
	# 
	global get_this: function(a: string): set[addr];
	global check_that: function(id: conn_id): bool;
}

# More consts and globals could be defined here if you do not want to provide
# access to them by other scripts.  Typically, internal tracking globals will
# be defined here that have no use outside of this script.
global skeleton_tracker: table[conn_id] of set[string] &create_expire=5mins;

# The logging framework needs initialized within a bro_init event which is 
# automatically generated while Bro is starting up.
event bro_init()
	{
	# The API for the logging framework can be found here:
	# <Create autodocumentation and link to it here>
	LOG::create_logs("skeleton", logging, split_log_file, T);
	LOG::define_header("skeleton", cat_sep("\t", "", "header1", 
	                                                 "header2", 
	                                                 "header3"));
	}


# Handle events and do some magic here!
#
# Keep in mind that some of the state
# you accumulate could be useful in other ways so be sure to let it accumulate
# in global variables that have been declared in the export section.  Be sure 
# you expire the data using the *_expire attributes too!  Filling up memory 
# makes your script much less useful. :)
#