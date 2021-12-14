### 2.3.90-20211213 ISO image built on 2021/12/13



### Download and Verify

2.3.90-20211213 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211213.iso

MD5: D7E90433B416627347DD54B7C3C07F18  
SHA1: 11E212B2237162749F5E3BD959C84D6C4720D213  
SHA256: 01DD0AF3CF5BBFD4AF7463F8897935A885E3D9CC8B9B3B5E9A01E0A2EF37ED95 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211213.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211213.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211213.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90-20211213.iso.sig securityonion-2.3.90-20211213.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 13 Dec 2021 11:46:27 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
