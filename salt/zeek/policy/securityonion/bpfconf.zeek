##! This script is to support the bpf.conf file like other network monitoring tools use.
##! Please don't try to learn from this script right now, there are a large number of
##! hacks in it to work around bugs discovered in Bro.

@load base/frameworks/notice

module BPFConf;

export {
	## The file that is watched on disk for BPF filter changes.
	## Two templated variables are available; "sensorname" and "interface".
	## They can be used by surrounding the term by doubled curly braces.
	const filename = "/opt/zeek/etc/bpf" &redef;

	redef enum Notice::Type += { 
		## Invalid filter notice.
		InvalidFilter
	};
}

global filter_parts: vector of string = vector();
global current_filter_filename = "";

type FilterLine: record {
	s: string;
};

redef enum PcapFilterID += {
	BPFConfPcapFilter,
};

event BPFConf::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local part = sub(s, /[[:blank:]]*#.*$/, "");

	# We don't want any blank parts.
	if ( part != "" )
		filter_parts[|filter_parts|] = part;
	}

event Input::end_of_data(name: string, source:string)
	{
	if ( name == "bpfconf" )
		{
		local filter = join_string_vec(filter_parts, " ");
		capture_filters["bpf.conf"] = filter;
		if ( Pcap::precompile_pcap_filter(BPFConfPcapFilter, filter) )
			{
			PacketFilter::install();
			}
		else
			{
			NOTICE([$note=InvalidFilter,
			        $msg=fmt("Compiling packet filter from %s failed", filename),
			        $sub=filter]);
			}

		filter_parts=vector();
		}
	}


function add_filter_file()
	{
	local real_filter_filename = BPFConf::filename;

	# Support the interface template value.
	#if ( SecurityOnion::sensorname != "" )
	#	real_filter_filename = gsub(real_filter_filename, /\{\{sensorname\}\}/, SecurityOnion::sensorname);

	# Support the interface template value.
	#if ( SecurityOnion::interface != "" )
	#	real_filter_filename = gsub(real_filter_filename, /\{\{interface\}\}/, SecurityOnion::interface);

	#if ( /\{\{/ in real_filter_filename )
	#	{
	#	return;
	#	}
	#else
	#	Reporter::info(fmt("BPFConf filename set: %s (%s)", real_filter_filename, Cluster::node));

	if ( real_filter_filename != current_filter_filename )
		{
		current_filter_filename = real_filter_filename;
		Input::add_event([$source=real_filter_filename,
		                  $name="bpfconf",
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $want_record=F,
		                  $fields=FilterLine,
		                  $ev=BPFConf::line]);
		}
	}

#event SecurityOnion::found_sensorname(name: string)
#	{
#	add_filter_file();
#	}

event zeek_init() &priority=5
	{
	if ( BPFConf::filename != "" )
		add_filter_file();
	}


