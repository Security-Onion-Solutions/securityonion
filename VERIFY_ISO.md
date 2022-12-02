### 2.3.190-20221202 ISO image built on 2022/12/02



### Download and Verify

2.3.190-20221202 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.190-20221202.iso

MD5: 451AD73084ACD0E30036C03BC8969AEC  
SHA1: 4EBC79E39F44AD78C02E9E2D6CCE3CF88D0E70BE  
SHA256: 8318A7B61DAFB677AD55A37AC2E09C59C10ACEA04B2489CBF2A1FB162DFC109A 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.190-20221202.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.190-20221202.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.190-20221202.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.190-20221202.iso.sig securityonion-2.3.190-20221202.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 02 Dec 2022 11:39:52 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
