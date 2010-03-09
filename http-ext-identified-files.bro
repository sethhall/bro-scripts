@load global-ext
@load http-ext

@load signatures
redef signature_files += "http-ext-identified-files.sig";

module HTTP;

export {
	redef enum Notice += {
		# This notice is thrown when the file extension doesn't 
		# seem to match the file contents.
		HTTP_IncorrectFileType, 
	};
	
	# MIME types that you'd like this script to identify and log.
	const watched_mime_types = /application\/x-dosexec/
	                         | /application\/x-executable/ &redef;
	
	# URLs included here are not logged and notices are not thrown.
	# Take care when defining regexes to not be overly broad.
	const ignored_urls = /^http:\/\/(au\.|www\.)?download\.windowsupdate\.com\/msdownload\/update/ &redef;
	
	# Create regexes that *should* in be in the urls for specifics mime types.
	# Notices are thrown if the pattern doesn't match the url for the file type.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

# Don't delete the http sessions at the end of the request!
redef watch_reply=T;

# Make the default signature action ignore anything beginning with "matchfile"
function default_signature_action(sig: string): SigAction
	{
	if ( /^matchfile-/ in sig )
		return SIG_IGNORE;
	else
		return SIG_ALARM;
	}
redef signature_actions &default=default_signature_action;

# This script uses the file tagging method to create a separate file.
event bro_init()
	{
	# Add the tag for log file splitting.
	LOG::define_tag("http-ext", "identified-files");
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	# Only signatures matching file types are dealt with here.
	if ( /^matchfile/ !in state$id ) return;
	
	# Not much point in any of this if we don't know about the 
	# HTTP-ness of the connection.
	if ( state$conn$id !in conn_info ) return;
	
	local si = conn_info[state$conn$id];
	# Set the mime type seen.
	si$mime_type = msg;
	
	if ( watched_mime_types in msg )
		{
		# Add a tag for logging purposes.
		add si$tags["identified-files"];
		}
		
	if ( ignored_urls !in si$url &&
	     msg in mime_types_extensions && 
	     mime_types_extensions[msg] !in si$url )
		{
		local message = fmt("%s %s %s", msg, si$method, si$url);
		NOTICE([$note=HTTP_IncorrectFileType, 
		        $msg=message, 
		        $conn=state$conn, 
		        $method=si$method, 
		        $URL=si$url]);
		}
	
	event file_transferred(state$conn, data, "", msg);
	}

