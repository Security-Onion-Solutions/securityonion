{
  "description" : "zeek.sip",
  "processors" : [
    { "remove":         { "field": ["host"],     "ignore_failure": true                                                                  } },
    { "json":		{ "field": "message",			"target_field": "message2",		"ignore_failure": true	} },
    { "rename": 	{ "field": "message2.trans_depth", 	"target_field": "sip.transaction.depth",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.method", 		"target_field": "sip.method",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.uri", 		"target_field": "sip.uri",			"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.date", 		"target_field": "sip.date",			"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.request_from", 	"target_field": "sip.request.from",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.request_to", 	"target_field": "sip.request.to",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.response_from", 	"target_field": "sip.response.from",	"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.response_to", 	"target_field": "sip.response.to",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.reply_to", 	"target_field": "sip.reply_to",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.call_id", 		"target_field": "sip.call_id",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.seq", 		"target_field": "sip.seq",			"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.subject", 		"target_field": "sip.subject",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.request_path", 	"target_field": "sip.request.path",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.response_path", 	"target_field": "sip.response.path",	"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.user_agent", 	"target_field": "client.user_agent",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.status_code", 	"target_field": "server.status_code",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.status_msg",	"target_field": "server.status_message",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.warning", 		"target_field": "sip.warning",		"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.request_body_len",	"target_field": "sip.request.body.length",	"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.response_body_len","target_field": "sip.response.body.length",	"ignore_missing": true 	} },
    { "rename": 	{ "field": "message2.content_type", 	"target_field": "sip.content_type",		"ignore_missing": true 	} },
    { "pipeline":       { "name": "zeek.common"                                                                                   } }
  ]
}
