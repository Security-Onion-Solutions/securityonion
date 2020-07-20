@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files
redef Intel::read_files += {
        "/opt/zeek/share/zeek/policy/intel/intel.dat"
};