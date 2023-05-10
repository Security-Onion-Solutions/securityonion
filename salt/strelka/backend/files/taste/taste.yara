// Archive Files

rule _7zip_file
{
    meta:
        type = "archive"
    strings:
        $a = { 37 7A BC AF 27 1C }
    condition:
        $a at 0
}

rule arj_file
{
    meta:
        type = "archive"
    condition:
        uint16(0) == 0xEA60
}

rule cab_file
{
    meta:
        type = "archive"
    strings:
        $a = { 4D 53 43 46 00 00 00 00 }
    condition:
        $a at 0 or
        ( uint16(0) == 0x5A4D and $a )
}

rule cpio_file
{
    meta:
        type = "archive"
    strings:
        $a = { 30 37 30 37 30 31 }
    condition:
        $a at 0
}

rule iso_file
{
    meta:
        type = "archive"
    strings:
        $a = { 43 44 30 30 31 }
    condition:
        $a at 0x8001 and $a at 0x8801 and $a at 0x9001
}

rule mhtml_file
{
    meta:
        type = "archive"
    strings:
        $a = "MIME-Version: 1.0"
        $b = "This document is a Single File Web Page, also known as a Web Archive file"
    condition:
        $a at 0 and $b
}

rule rar_file
{
    meta:
        type = "archive"
    condition:
        uint16(0) == 0x6152 and uint8(2) == 0x72 and uint16(3) == 0x1A21 and uint8(5) == 0x07
}

rule tar_file
{
    meta:
        type = "archive"
    strings:
        $a = { 75 73 74 61 72 }
    condition:
        uint16(0) == 0x9D1F or
        uint16(0) == 0xA01F or
        $a at 257
}

rule xar_file
{
    meta:
        type = "archive"
    condition:
        uint32(0) == 0x21726178
}

rule zip_file
{
    meta:
        type = "archive"
    condition:
        ( uint32(0) == 0x04034B50 and not uint32(4) == 0x00060014 )
}

// Audio Files

rule mp3_file
{
    meta:
        type = "audio"
    condition:
        uint16(0) == 0x4449 and uint8(2) == 0x33
}

// Certificate Files

rule pkcs7_file
{
    meta:
        type = "certificate"
    strings:
        $a = "-----BEGIN PKCS7-----"
    condition:
        (uint16(0) == 0x8230 and uint16(4) == 0x0906) or
        uint32(0) == 0x09068030 or
        $a at 0
}

rule x509_der_file
{
    meta:
        type = "certificate"
    condition:
        uint16(0) == 0x8230 and ( uint16(4) == 0x8230 or uint16(4) == 0x8130 )
}

rule x509_pem_file
{
    meta:
        type = "certificate"
    strings:
        $a = "-----BEGIN CERTI"
    condition:
        $a at 0
}

// Compressed Files

rule bzip2_file
{
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x5A42 and uint8(2) == 0x68
}

rule gzip_file
{
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x8B1F and uint8(2) == 0x08
}

rule lzma_file
{
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x005D and uint8(2) == 0x00
}

rule xz_file
{
    meta:
        type = "compressed"
    condition:
        uint32(0) == 0x587A37FD and uint16(4) == 0x005A
}

// Document Files

rule doc_subheader_file
{
    meta:
        type = "document"
    condition:
        uint32(0) == 0x00C1A5EC
}

rule mso_file
{
    meta:
        type = "document"
    strings:
        $a = { 3C 3F 6D 73 6F 2D 61 70 70 6C 69 63 61 74 69 6F 6E 20 } // <?mso-application
        $b = { 3C 3F 6D 73 6F 2D 63 6F 6E 74 65 6E 74 54 79 70 65 } // <?mso-contentType
    condition:
        $a at 0 or
        $b at 0
}

rule olecf_file
{
    meta:
        description = "Object Linking and Embedding (OLE) Compound File (CF)"
        type = "document"
    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1
}

rule ooxml_file
{
    meta:
        description = "Microsoft Office Open XML Format"
        type  = "document"
    condition:
        uint32(0) == 0x04034B50 and uint32(4) == 0x00060014
}

rule pdf_file
{
    meta:
        description = "Portable Document Format"
        type = "document"
    condition:
        uint32(0) == 0x46445025
}

rule poi_hpbf_file
{
    meta:
        description = "https://poi.apache.org/components/hpbf/file-format.html"
        type = "document"
    strings:
        $a = { 43 48 4E 4B 49 4E 4B } // CHNKINK
    condition:
        $a at 0
}

rule rtf_file
{
    meta:
        type = "document"
    condition:
        uint32(0) == 0x74725C7B
}

rule vbframe_file
{
    meta:
        type = "document"
    strings:
        $a = { 56 45 52 53 49 4F 4E 20 35 2E 30 30 0D 0A 42 65 67 69 6E } // VERSION 5.00\r\nBegin
    condition:
        $a at 0
}

rule wordml_file
{
    meta:
        description = "Microsoft Office Word 2003 XML format"
        type = "document"
    strings:
       $a = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D } // <?xml version=
       $b = "http://schemas.microsoft.com/office/word/2003/wordml"
    condition:
        $a at 0 and $b
}

rule xfdf_file
{
    meta:
        description = "XML Forms Data Format"
        type = "document"
    strings:
        $a = { 3C 78 66 64 66 20 78 6D 6C 6E 73 3D } // <xfdf xmlns=
    condition:
        $a at 0
}

// Email Files

rule email_file
{
    meta:
        type = "email"
    strings:
        $a = "\x0aReceived:" nocase fullword
        $b = "\x0AReturn-Path:" nocase fullword
        $c = "\x0aMessage-ID:" nocase fullword
        $d = "\x0aReply-To:" nocase fullword
        $e = "\x0aX-Mailer:" nocase fullword
    condition:
        $a in (0..2048) or
        $b in (0..2048) or
        $c in (0..2048) or
        $d in (0..2048) or
        $e in (0..2048)
}

rule tnef_file
{
    meta:
        description = "Transport Neutral Encapsulation Format"
        type = "email"
    condition:
        uint32(0) == 0x223E9F78
}

// Encryption Files

rule pgp_file
{
    meta:
        type = "encryption"
    strings:
        $a = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 50 55 42 4C 49 43 20 4B 45 59 20 42 4C 4F 43 4B 2D } // (.{2})(\x2D\x2D\x2DBEGIN PGP PUBLIC KEY BLOCK\x2D)
        $b = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 53 49 47 4E 41 54 55 52 45 2D } // (\x2D\x2D\x2D\x2D\x2DBEGIN PGP SIGNATURE\x2D)
        $c = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 4D 45 53 53 41 47 45 2D } // (\x2D\x2D\x2D\x2D\x2DBEGIN PGP MESSAGE\x2D)
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0
}

// Executable Files

rule elf_file
{
    meta:
        description = "Executable and Linkable Format"
        type = "executable"
    condition:
        uint32(0) == 0x464C457F
}

rule lnk_file
{
    meta:
        description = "Windows Shortcut file"
        type = "executable"
    condition:
        uint32(0) == 0x0000004C
}

rule macho_file
{
    meta:
        description = "Mach object"
        type = "executable"
    condition:
        uint32(0) == 0xCEFAEDFE or
        uint32(0) == 0xCFFAEDFE or
        uint32(0) == 0xFEEDFACE or
        uint32(0) == 0xFEEDFACF
}

rule mz_file
{
    meta:
        description = "DOS MZ executable"
        type = "executable"
    condition:
        uint16(0) == 0x5A4D
}

// Image Files

rule bmp_file
{
    meta:
        type = "image"
    strings:
        $a = { 42 4D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ( 0C | 28 | 40 | 6C | 7C | 80 ) 00 } // BM
    condition:
        $a at 0
}

rule cmap_file
{
    meta:
        type = "image"
    strings:
        $a = { 62 65 67 69 6E 63 6D 61 70 } // begincmap
    condition:
        $a at 0
}

rule gif_file
{
    meta:
        description = "Graphics Interchange Format"
        type = "image"
    condition:
        uint32(0) == 0x38464947 and ( uint16(4) == 0x6137 or uint16(4) == 0x6139 )
}

rule jpeg_file
{
    meta:
        type = "image"
    condition:
        uint32(0) == 0xE0FFD8FF or
        uint32(0) == 0xE1FFD8FF or
        uint32(0) == 0xE2FFD8FF or
        uint32(0) == 0xE8FFD8FF
}

rule postscript_file
{
    meta:
        type = "image"
    strings:
        $a = { 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 } // %!PS-Adobe-3.0
    condition:
        $a at 0
}

rule png_file
{
    meta:
        type = "image"
    condition:
        uint32(0) == 0x474E5089
}

rule psd_file
{
    meta:
        description = "Photoshop Document"
        type = "image"
    condition:
        uint32(0) == 0x53504238
}

rule psd_image_file
{
    meta:
        description = "Photoshop Document image resource block"
        type = "image"
    condition:
        uint32(0) == 0x4D494238
}

rule svg_file
{
    meta:
        type = "image"
    strings:
        $a = { 3C 73 76 67 20 } // <svg
    condition:
        $a at 0
}

rule xicc_file
{
    meta:
        type = "image"
    strings:
        $a = { 58 49 43 43 5F 50 52 4F 46 49 4C 45 } // XICC_PROFILE
    condition:
        $a at 0
}

rule xmp_file
{
    meta:
        type = "image"
    strings:
        $a = { 3C 3F 78 70 61 63 6B 65 74 20 62 65 67 69 6E 3D } // <?xpacket begin=
        $b = { 3C 78 3A 78 6D 70 6D 65 74 61 20 78 6D 6C 6E 73 3A 78 3D } // <x:xmpmeta xmlns:x=
    condition:
        $a at 0 or $b at 0
}

// Metadata Files

rule jar_manifest_file
{
    meta:
        type = "metadata"
    condition:
        uint32(0) == 0x696E614D and uint32(4) == 0x74736566
}

rule bplist_file
{
    meta:
        description = "Binary Property List"
        type = "metadata"
    condition:
        uint32(0) == 0x696C7062 and uint32(4) == 0x30307473
}

// Multimedia Files

rule fws_file
{
    meta:
        type =  "multimedia"
    condition:
        uint16(0) == 0x5746 and uint8(2) == 0x53
}

rule cws_file
{
    meta:
        description = "zlib compressed Flash file"
        type = "multimedia"
    condition:
        uint16(0) == 0x5743 and uint8(2) == 0x53
}


rule zws_file
{
    meta:
        description = "LZMA compressed Flash file"
        type =  "multimedia"
    condition:
        uint16(0) == 0x575A and uint8(2) == 0x53
}

// Package Files

rule debian_package_file
{
    meta:
        type = "package"
    strings:
        $a = { 21 3C 61 72 63 68 3E 0A 64 65 62 69 61 6E } // \x21\x3Carch\x3E\x0Adebian
    condition:
        $a at 0
}

rule rpm_file
{
    meta:
        type = "package"
    condition:
        uint32(0) == 0x6D707264 or uint32(0) == 0xDBEEABED
}

// Packer Files

rule upx_file
{
    meta:
        description = "Ultimate Packer for Executables"
        type = "packer"
    strings:
        $a = {55505830000000}
        $b = {55505831000000}
        $c = "UPX!"
    condition:
        uint16(0) == 0x5A4D and
        $a in (0..1024) and
        $b in (0..1024) and
        $c in (0..1024)
}

// Script Files

rule batch_file
{
    meta:
        type = "script"
    strings:
        $a = { ( 45 | 65 ) ( 43 | 63 ) ( 48 | 68 ) ( 4F | 6F ) 20 ( 4F | 6F) ( 46 | 66 ) ( 46 | 66 ) } // [Ee][Cc][Hh][Oo] [Oo][Ff][Ff]
    condition:
        $a at 0
}

rule javascript_file
{
    meta:
        type = "script"
    strings:
        $var = { 76 61 72 20 } // var
        $function1 = { 66 75 6E 63 74 69 6F 6E } // function
        $function2 = { 28 66 75 6E 63 74 69 6F 6E } // (function
        $function3 = { 66 75 6E 63 74 69 6F 6E [0-1] 28 } // function[0-1](
        $if = { 69 66 [0-1] 28 } // if[0-1](
        $misc1 = { 24 28 } // $(
        $misc2 = { 2F ( 2A | 2F ) } // \/(\/|\*)
        $jquery = { 6A 51 75 65 72 79 } // jQuery
        $try = { 74 72 79 [0-1] 7B } // try[0-1]{
        $catch = { 63 61 74 63 68 28 } // catch(
        $push = { 2E 70 75 73 68 28 } // .push(
        $array = { 6E 65 77 20 41 72 72 61 79 28 } // new Array(
        $document1 = { 64 6f 63 75 6d 65 6e 74 2e 63 72 65 61 74 65 } // document.create
        $document2 = { 64 6F 63 75 6D 65 6E 74 2E 77 72 69 74 65 } // document.write
        $window = { 77 69 6E 64 6F 77 ( 2E | 5B ) } // window[.\[]
        $define = { 64 65 66 69 6E 65 28 } // define(
        $eval = { 65 76 61 6C 28 } // eval(
        $unescape = { 75 6E 65 73 63 61 70 65 28 } // unescape(
    condition:
        $var at 0 or
        $function1 at 0 or
        $function2 at 0 or
        $if at 0 or
        $jquery at 0 or
        $function3 in (0..30) or
        $push in (0..30) or
        $array in (0..30) or
        ( $try at 0 and $catch in (5..5000) ) or
        $document1 in (0..100) or
        $document2 in (0..100) or
        $window in (0..100) or
        $define in (0..100) or
        $eval in (0..100) or
        $unescape in (0..100) or
        ( ( $misc1 at 0 or $misc2 at 0 ) and $var and $function1 and $if )
}

rule vb_file
{
    meta:
        type = "script"
    strings:
        $a = { 41 74 74 72 69 62 75 74 65 20 56 42 5F 4E 61 6D 65 20 3D } // Attribute VB_Name =
        $b = { 4F 70 74 69 6F 6E 20 45 78 70 6C 69 63 69 74 } // Option Explicit
        $c = { 44 69 6D 20 } // Dim
        $d = { 50 75 62 6C 69 63 20 53 75 62 20 } // Public Sub
        $e = { 50 72 69 76 61 74 65 20 53 75 62 20 } // Private Sub
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0
}

// Text Files

rule hta_file
{
    meta:
        type = "text"
    strings:
        $a = { 3C 48 54 41 3A 41 50 50 4C 49 43 41 54 49 4F 4E 20 } // <HTA:APPLICATION
    condition:
        $a in (0..2000)
}

rule html_file
{
    meta:
        type = "text"
    strings:
        $a = { 3C 21 ( 64 | 44 ) ( 6F | 4F ) ( 63 |43 ) ( 74 | 54 ) ( 79 | 59 ) ( 70 | 50 ) ( 65 | 45 )  20 ( 68 | 48 ) ( 74 | 54 ) ( 6D | 4D ) ( 6C | 4C )  } // <![Dd][Oo][Cc][Tt][Yy][Pp][Ee] [Hh][Tt][Mm][Ll]
        $b = { 3C ( 68 | 48 ) ( 74 | 54 ) ( 6D | 4D ) ( 6C | 4C ) } // <[Hh][Tt][Mm][Ll]
        $c = { 3C ( 62 | 42 ) ( 72 | 52 ) } // <br
        $d = { 3C ( 44 | 64 ) ( 49 | 69 ) ( 56 | 76 ) } // <[Dd][Ii][Vv]
        $e = { 3C ( 41 | 61 ) 20 ( 48 |68 ) ( 52 | 72 ) ( 45 | 65 ) ( 46 | 66 ) 3D } // <[Aa] [Hh][Rr][Ee][Ff]=
        $f = { 3C ( 48 | 68 ) ( 45 | 65 ) ( 41 | 61 ) ( 44 | 64 ) } // <[Hh][Ee][Aa][Dd]
        $g = { 3C ( 53 | 73 ) ( 43 | 63 ) ( 52 | 72 ) ( 49 | 69 ) ( 50 | 70 ) ( 54 | 74 ) } // <[Ss][Cc][Rr][Ii][Pp][Tt]
        $h = { 3C ( 53 | 73 ) ( 54 | 74 ) ( 59 | 79 ) ( 4C | 6C ) ( 45 | 65 ) } // <[Ss][Tt][Yy][Ll][Ee]
        $i = { 3C ( 54 | 74 ) ( 41 | 61 ) ( 42 | 62 ) ( 4C | 6C ) ( 45 | 65 ) } // <[Tt][Aa][Bb][Ll][Ee]
        $j = { 3C ( 50 | 70 ) } // <[Pp]
        $k = { 3C ( 49 | 69 ) ( 4D | 6D ) ( 47 | 67 ) } // <[Ii][Mm][Gg]
        $l = { 3C ( 53 | 73 ) ( 50 |70 ) ( 41 | 61 ) ( 4E | 6E ) } // <[Ss][Pp][Aa][Nn]
        $m = { 3C ( 48 | 68 ) ( 52 | 72 | 31 | 32 | 33 | 34 | 35 | 36 ) } // <[Hh][Rr] <[Hh][1-6]
        $n = { 3C ( 54 | 74) ( 49 | 69 ) ( 54 | 74 ) ( 4C | 6C ) ( 45 | 65 ) 3E } // <[Tt][Ii][Tt][Ll][Ee]>
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0 or
        $f at 0 or
        $g at 0 or
        $h at 0 or
        $i at 0 or
        $j at 0 or
        $k at 0 or
        $l at 0 or
        $m at 0 or
        $n at 0
}

rule json_file
{
    meta:
        type = "text"
    strings:
        $a = { 7B [0-5] 22 }
    condition:
        $a at 0
}

rule php_file
{
    meta:
        type = "text"
    strings:
        $a = { 3c 3f 70 68 70 }
    condition:
        $a at 0
}

rule soap_file
{
    meta:
        description = "Simple Object Access Protocol"
        type = "text"
    strings:
        $a = { 3C 73 6F 61 70 65 6E 76 3A 45 6E 76 65 6C 6F 70 65 } // <soapenv:Envelope xmlns
        $b = { 3C 73 3A 45 6E 76 65 6C 6F 70 65 } // <s:Envelope
    condition:
        $a at 0 or
        $b at 0
}

rule xml_file
{
    meta:
        type = "text"
    strings:
        $a = { 3C 3F ( 58 | 78) ( 4D | 6D ) ( 4C | 6C ) 20 76 65 72 73 69 6F 6E 3D } // <?[Xx][Mm][Ll] version=
        $b = { 3C 3F 78 6D 6C 3F 3E } // <?xml?>
        $c = { 3C 73 74 79 6C 65 53 68 65 65 74 20 78 6D 6C 6E 73 3D } // <styleSheet xmlns=
        $d = { 3C 77 6F 72 6B 62 6F 6F 6B 20 78 6D 6C 6E 73 } // <workbook xmlns
        $e = { 3C 78 6D 6C 20 78 6D 6C 6E 73 } // <xml xmlns
        $f = { 3C 69 6E 74 20 78 6D 6C 6E 73 } // <int xmlns
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0 or
        $f at 0
}

// Video Files

rule avi_file
{
    meta:
        type = "video"
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 4C 49 53 54 }
    condition:
        $a at 0
}

rule wmv_file
{
    meta:
        type = "video"
    condition:
        uint32(0) == 0x75B22630 and uint32(4) == 0x11CF668E and uint32(8) == 0xAA00D9A6 and uint32(12) == 0x6CCE6200
}
