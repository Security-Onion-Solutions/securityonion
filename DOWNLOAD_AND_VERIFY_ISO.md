### 3.2.0-20260729 ISO image released on 2026/07/29


### Download and Verify

3.2.0-20260729 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.2.0-20260729.iso
 
MD5: B1E10F46DF872B655C29325DF965A4DB  
SHA1: 0F3C7ED80F6D326B7A993C2F899B986320C01BF9  
SHA256: 7465163C1D1ADFCDC3935530EAFB312E987C016941ADC11841B214553314D1FF  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.2.0-20260729.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.2.0-20260729.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.2.0-20260729.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.2.0-20260729.iso.sig securityonion-3.2.0-20260729.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 28 Jul 2026 06:17:34 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
