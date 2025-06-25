##! Extends community ID logging to Files, and SSL by copying
##! the community_id from the parent connection.
##!
##! Note: Requires that protocols/conn/community-id-logging is loaded

module CommunityIDExt;

@load base/protocols/ssl
@load protocols/conn/community-id-logging

export {
    redef record SSL::Info += {
        community_id: string &optional &log;
    };

    redef record Files::Info += {
        community_id: string &optional &log;
    };
}

# Files
event file_new(f: fa_file) {
    if ( f?$conns ) {
        # Take community_id from first connection that has it
        for ( cid in f$conns ) {
            local c = f$conns[cid];
            if ( c?$conn && c$conn?$community_id ) {
                f$info$community_id = c$conn$community_id;
                break;
            }
        }
    }
}

# SSL Connections
event ssl_established(c: connection) {
    if ( c?$conn && c$conn?$community_id && c?$ssl ) {
        c$ssl$community_id = c$conn$community_id;
    }
}
