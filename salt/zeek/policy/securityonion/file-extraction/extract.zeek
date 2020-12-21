{% import_yaml "zeek/fileextraction_defaults.yaml" as zeek_default -%}
{% set zeek = salt['grains.filter_by'](zeek_default, default='zeek', merge=salt['pillar.get']('zeek', {})) -%}
# Directory to stage Zeek extracted files before processing
redef FileExtract::prefix = "/nsm/zeek/extracted/";
# Set a limit to the file size
redef FileExtract::default_limit = 9000000;
# These are the mimetypes we want to rip off the networks
export {
    global _mime_whitelist: table[string] of string = {
        {%- for li in zeek.policy.file_extraction %}
          {%- if not loop.last %}
          {%- for k,v in li.items() %}
        ["{{ k }}"] = "{{ v }}",
          {%- endfor %}
          {%- else %}
          {%- for k,v in li.items() %}
        ["{{ k }}"] = "{{ v }}"
          {%- endfor %}
          {%- endif %}
        {%- endfor %}
        };
}
# Start grabbing the file from the network if it matches the mimetype
event file_sniff(f: fa_file, meta: fa_metadata) &priority=10 {
    local ext = "";
    if( meta?$mime_type ) {
    if ( meta$mime_type !in _mime_whitelist ) {
          return;
    }
    ext = _mime_whitelist[meta$mime_type];
    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
        }
}
# Wait for file_state_remove before you do anything. This is when it is actually done.
event file_state_remove(f: fa_file)
        {
        if ( !f$info?$extracted || FileExtract::prefix == "" ) {
                return;
        }
        # Check some conditions so we know the file is intact:
        # Check for MD5
        # Check for total_bytes
        # Check for missing bytes
        # Check if timed out
        if ( !f$info?$md5 || !f?$total_bytes || f$missing_bytes > 0 || f$info$timedout) {
          # Delete the file if it didn't pass our requirements check.

          local nuke = fmt("rm %s/%s", FileExtract::prefix, f$info$extracted);
          when ( local nukeit = Exec::run([$cmd=nuke]) )
                    {
                    }
                    return;
        }
        local orig = f$info$extracted;
        local split_orig = split_string(f$info$extracted, /\./);
        local extension = split_orig[|split_orig|-1];
        local dest = fmt("%scomplete/%s-%s-%s.%s", FileExtract::prefix, f$source, f$id, f$info$md5, extension);
        # Copy it to the $prefix/complete folder then delete it. I got some weird results with moving when it came to watchdog in python.
        local cmd = fmt("cp %s/%s %s && rm %s/%s", FileExtract::prefix, orig, dest, FileExtract::prefix, orig);
      when ( local result = Exec::run([$cmd=cmd]) )
                {
                }
      f$info$extracted = dest;
        }

