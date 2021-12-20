### 2.3.91 ISO image built on 2021/12/20



### Download and Verify

2.3.91 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.91.iso

MD5: CD979038EC60318B7C7F8BA278A12D04
SHA1: 9FB2AC07FCD24A4993B3F61FC2B2863510650520
SHA256: BAA8BEF574ECCB9ADC326D736A00C00AAF940FC6AD68CF491FF1F0AB6C5BAA64

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.91.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.91.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.91.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.91.iso.sig securityonion-2.3.91.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 20 Dec 2021 12:37:42 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
