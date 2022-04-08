### 2.3.110-20220407 ISO image built on 2022/04/07



### Download and Verify

2.3.110-20220407 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220407.iso

MD5: 928D589709731EFE9942CA134A6F4C6B  
SHA1: CA588A684586CC0D5BDE5E0E41C935FFB939B6C7  
SHA256: CBF8743838AF2C7323E629FB6B28D5DD00AE6658B0E29E4D0916411D2D526BD2 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220407.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220407.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220407.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.110-20220407.iso.sig securityonion-2.3.110-20220407.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 07 Apr 2022 03:30:03 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
