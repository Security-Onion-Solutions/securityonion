### 2.3.52 ISO image built on 2021/04/27



### Download and Verify

2.3.52 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.52.iso

MD5: DF0CCCB0331780F472CC167AEAB55652  
SHA1: 71FAE87E6C0AD99FCC27C50A5E5767D3F2332260  
SHA256: 30E7C4206CC86E94D1657CBE420D2F41C28BC4CC63C51F27C448109EBAF09121 

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
gpg: Signature made Sat 05 Jun 2021 06:56:04 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
