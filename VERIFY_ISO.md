### 2.3.170-20220922 ISO image built on 2022/09/22



### Download and Verify

2.3.170-20220922 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.170-20220922.iso

MD5: B45E38F72500CF302AE7CB3A87B3DB4C  
SHA1: 06EC41B4B7E55453389952BE91B20AA465E18F33  
SHA256: 634A2E88250DC7583705360EB5AD966D282FAE77AFFAF81676CB6D66D7950A3E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.170-20220922.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.170-20220922.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.170-20220922.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.170-20220922.iso.sig securityonion-2.3.170-20220922.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 22 Sep 2022 11:48:42 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
