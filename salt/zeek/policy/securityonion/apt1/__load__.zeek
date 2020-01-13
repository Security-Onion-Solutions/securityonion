@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files

redef Intel::read_files += {
  fmt("%s/apt1-fqdn.dat", @DIR),
  fmt("%s/apt1-md5.dat", @DIR),
  fmt("%s/apt1-certs.dat", @DIR)
};
