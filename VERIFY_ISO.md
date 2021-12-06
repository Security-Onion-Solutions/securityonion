### 2.3.90-20211206 ISO image built on 2021/12/06



### Download and Verify

2.3.90-20211206 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211206.iso

MD5: 8A5FDF731D548E27D123E5B711890AEC  
SHA1: B4AF33FE1D64592D46C780AF0C5E7FBD21A22BDE  
SHA256: 091DA2D06C82447639D324EE32DBC385AE407078B3A55F4E0704B22DB6B29A7E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211206.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211206.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211206.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90-20211206.iso.sig securityonion-2.3.90-20211206.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 06 Dec 2021 10:14:29 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
