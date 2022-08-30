### 2.3.160-20220829 ISO image built on 2022/08/29



### Download and Verify

2.3.160-20220829 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.160-20220829.iso

MD5: CED26ED960F4F778DB59FB9A4AEC88A7  
SHA1: FF4934B4C76277A88366129FB5F1373A5CF27009  
SHA256: 5648846866676F7C92DA0BDBB0503EF9C73E2C58A3C11FE87F041C100A22F795 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.160-20220829.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.160-20220829.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.160-20220829.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.160-20220829.iso.sig securityonion-2.3.160-20220829.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 29 Aug 2022 12:03:30 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
