### 2.4.100-20240903 ISO image released on 2024/09/03


### Download and Verify

2.4.100-20240903 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.100-20240903.iso
 
MD5: 856BBB4F0764C0A479D8949725FC096B  
SHA1: B3FCFB8F1031EB8AA833A90C6C5BB61328A73842  
SHA256: 0103EB9D78970396BB47CBD18DA1FFE64524F5C1C559487A1B2D293E1882B265  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.100-20240903.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.100-20240903.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.100-20240903.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.100-20240903.iso.sig securityonion-2.4.100-20240903.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sat 31 Aug 2024 05:05:05 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
