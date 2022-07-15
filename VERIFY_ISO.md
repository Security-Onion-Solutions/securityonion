### 2.3.140-20220715 ISO image built on 2022/06/07



### Download and Verify

2.3.140-20220715 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220715.iso

MD5: C3A6197DE75D0B0933536143B9CB977E  
SHA1: 47F3BA9771AACA9712484C47DB5FB67D1230D8F0  
SHA256: CC3485C23C6CE10855188D7015EEA495F6846A477187D378057B6C88F6B8C654 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220715.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220715.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220715.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.140-20220715.iso.sig securityonion-2.3.140-20220715.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 15 Jul 2022 11:52:40 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
