### 2.4.201-20260114 ISO image released on 2026/1/15


### Download and Verify

2.4.201-20260114 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.201-20260114.iso
 
MD5: 20E926E433203798512EF46E590C89B9  
SHA1: 779E4084A3E1A209B494493B8F5658508B6014FA  
SHA256: 3D10E7C885AEC5C5D4F4E50F9644FF9728E8C0A2E36EBB8C96B32569685A7C40  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.201-20260114.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.201-20260114.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.201-20260114.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.201-20260114.iso.sig securityonion-2.4.201-20260114.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 14 Jan 2026 05:23:39 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
