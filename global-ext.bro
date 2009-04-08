@load site
@load functions-ext

const private_address_space: set[subnet] = {10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8, 172.16.0.0/12};

# This defines the event that is used by the bro-dblogger application
# to push data from Bro directly into a database.
#  see: http://github.com/sethhall/bro-dblogger/tree/master
global db_log: event(db_table: string, data: any);
