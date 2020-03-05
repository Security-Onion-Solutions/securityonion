 Hit up TOoSmOotH with questions
# Directory to stage Zeek extracted files before processing
redef FileExtract::prefix = "/nsm/zeek/extracted/";
# Set a limit to the file size
redef FileExtract::default_limit = 9000000;
# These are the mimetypes we want to rip off the networks
export {
    global _mime_whitelist: table[string] of string = {
        ["application/x-dosexec"] = "exe",
        ["application/pdf"] = "pdf",
        ["application/msword"] = "doc",
        ["application/vnd.ms-powerpoint"] = "doc",
        ["application/rtf"] = "doc",
        ["application/vnd.ms-word.document.macroenabled.12"] = "doc",
        ["application/vnd.ms-word.template.macroenabled.12"] = "doc",
        ["application/vnd.ms-powerpoint.template.macroenabled.12"] = "doc",
        ["application/vnd.ms-excel"] = "doc",
        ["application/vnd.ms-excel.addin.macroenabled.12"] = "doc",
        ["application/vnd.ms-excel.sheet.binary.macroenabled.12"] = "doc",
        ["application/vnd.ms-excel.template.macroenabled.12"] = "doc",
        ["application/vnd.ms-excel.sheet.macroenabled.12"] = "doc",
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "doc",
        ["application/vnd.openxmlformats-officedocument.presentationml.slide"] = "doc",
        ["application/vnd.openxmlformats-officedocument.presentationml.slideshow"] = "doc",
        ["application/vnd.openxmlformats-officedocument.presentationml.template"] = "doc",
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "doc",
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.template"] = "doc",
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "doc",
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.template"] = "doc",
        ["application/vnd.ms-powerpoint.addin.macroenabled.12"] = "doc",
        ["application/vnd.ms-powerpoint.slide.macroenabled.12"] = "doc",
        ["application/vnd.ms-powerpoint.presentation.macroenabled.12"] = "doc",
        ["application/vnd.ms-powerpoint.slideshow.macroenabled.12"] = "doc",
        ["application/vnd.openxmlformats-officedocument"] = "doc"
        # Need to add other types such as zip, ps1, etc
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

