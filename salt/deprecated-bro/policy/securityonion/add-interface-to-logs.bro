{%- set interface = salt['pillar.get']('sensor:interface', '0') %}
global interface = "{{ interface }}";

event bro_init()
	{
	if ( ! reading_live_traffic() )
		return;

	Log::remove_default_filter(HTTP::LOG);
	Log::add_filter(HTTP::LOG, [$name = "http-interfaces",
	                            $path_func(id: Log::ID, path: string, rec: HTTP::Info) =
	                            	{
	                            	local peer = get_event_peer()$descr;
	                            	if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface )
	                            		return cat("http_", Cluster::nodes[peer]$interface);
	                            	else
	                            		return "http";
	                            	}
	                            ]);
	}
