### 2.3.10 ISO image built on 2020/11/19

### Download and Verify

2.3.10 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.10.iso

MD5: 2043701FC0FE785A877ECAE74CD73694  
SHA1: 15AE0B332DAF91C7895FDBEB1FCF900D6ECA8299  
SHA256: 4CD3FB9335F0AA00339D0F76D03867439BF963169C47C0CF43C82A18C6F32830 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.10.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.10.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.10.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.10.iso.sig securityonion-2.3.10.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 19 Nov 2020 10:22:55 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
