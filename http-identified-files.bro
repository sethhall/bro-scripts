@load http
@load global-ext

module HTTP;

export {
	const http_magic_log = open_log_file("http-identified-files") &raw_output &redef;

	# Base the libmagic analysis on at least this many bytes.
	const magic_content_limit = 1024 &redef;
	
	const watched_mime_types: set[string] = { 
		"application/x-dosexec",      # Windows and DOS executables
		"application/x-executable",   # *NIX executable binary
	} &redef; 
	
	const watched_descriptions =
		/PHP script text/ &redef;
	
	# URLs included here are not logged and notices are not thrown.
	# Take care when defining regexes to not be overly broad.
	const ignored_urls = /^http:\/\/www\.download\.windowsupdate\.com\// &redef;
	
	redef enum Notice += {
		# This notice is thrown when the file extension doesn't match the file contents
		HTTP_IncorrectFileType, 
	};
	
	# Create regexes that *should* in be in the urls for specifics mime types.
	# Notices are thrown if the pattern doesn't match the url for the file type.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( is_orig ) # We are only watching for server responses
		return;
	
	local s = lookup_http_request_stream(c);
	local msg = get_http_message(s, is_orig);
	
@ifndef	( content_truncation_limit )
	# This is only done if http-body.bro is not loaded.
	msg$data_length = msg$data_length + length;
@endif
	
	# For the time being, we'll just use the data from the first packet.
	# Don't continue until we have enough data
	#if ( msg$data_length < magic_content_limit )
	#	return;
	
	# Right now, only try this for the first chunk of data
	if ( msg$data_length > length )
		return;
	
	local abstract = sub_bytes(data, 1, magic_content_limit);
	local magic_mime = identify_data(abstract, T);
	local magic_descr = identify_data(abstract, F);

	if ( (magic_mime in watched_mime_types ||
	      watched_descriptions in magic_descr) &&
	     s$first_pending_request in s$requests )
		{
		local r = s$requests[s$first_pending_request];
		local host = (s$next_request$host=="") ? fmt("%s", c$id$resp_h) : s$next_request$host;
		local url = fmt("http://%s%s", host, r$URI);
		
		event file_transferred(c, abstract, magic_descr, magic_mime);
		
		if ( ignored_urls in url )
			return;
		
		local file_type = "";
		if ( magic_mime in watched_mime_types )
			file_type = magic_mime;
		else
			file_type = magic_descr;
		
		print http_magic_log, cat_sep("\t", "\\N", network_time(), s$id, 
		                                           c$id$orig_h, fmt("%d", c$id$orig_p), 
		                                           c$id$resp_h, fmt("%d", c$id$resp_p), 
		                                           file_type, r$method, url);
		
		if ( (magic_mime in mime_types_extensions && 
		      mime_types_extensions[magic_mime] !in url) ||
		     (magic_descr in mime_types_extensions && 
		      mime_types_extensions[magic_descr] !in url) )
			{
			local message = fmt("%s %s %s", file_type, r$method, url);
			NOTICE([$note=HTTP_IncorrectFileType, 
			        $msg=message, 
			        $conn=c, 
			        $method=r$method, 
			        $URL=url]);
			}
		}
	}


