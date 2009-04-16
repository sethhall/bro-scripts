signature ssn-match {
	ip-proto == tcp
	payload /.*[^0-9\/]\0?[0-6](\0?[0-9]){2}\0?[ \-]?(\0?[0-9]){2}\0?[ \-]?(\0?[0-9]){4}(\0?[[:blank:]\r\n<\"\'])/
	eval SSN::validate_ssn_match
}
