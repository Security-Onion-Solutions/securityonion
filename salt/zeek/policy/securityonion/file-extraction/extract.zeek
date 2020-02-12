global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type || meta$mime_type != "application/x-dosexec" )
        return;

    local ext = "";

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];

    local fname = fmt("/nsm/bro/extracted/%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
