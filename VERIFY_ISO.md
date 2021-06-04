### 2.3.52 ISO image built on 2021/04/27


### Download and Verify

2.3.52 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.52.iso

MD5: 7CFB525BEFC0A9F2ED148F5831E387FA  
SHA1: 8CC34FCCC36822B309B8168AA706B3D1EC7F3BFD  
SHA256: 9892C2546C9AE5A48015160F379B070F0BE30C89693B97F3F1E1592DDCE1DEE0 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.52.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.52.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.52.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.52.iso.sig securityonion-2.3.52.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 03 Jun 2021 03:28:42 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
