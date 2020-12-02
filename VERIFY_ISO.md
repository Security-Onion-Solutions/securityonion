### 2.3.10 ISO image built on 2020/11/19

### Download and Verify

2.3.10 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.10.iso

MD5: 55E10BAE3D90DF47CA4D5DCCDCB67A96  
SHA1: 01361123F35CEACE077803BC8074594D57EE653A  
SHA256: 772EA4EFFFF12F026593F5D1CC93DB538CC17B9BA5F60308F1976B6ED7032A8D 

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
gpg: Signature made Thu 19 Nov 2020 03:38:54 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
