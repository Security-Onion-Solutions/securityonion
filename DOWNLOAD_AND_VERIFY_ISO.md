### 2.4.200-20251216 ISO image released on 2025/12/16


### Download and Verify

2.4.200-20251216 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.200-20251216.iso
 
MD5: 07B38499952D1F2FD7B5AF10096D0043  
SHA1: 7F3A26839CA3CAEC2D90BB73D229D55E04C7D370  
SHA256: 8D3AC735873A2EA8527E16A6A08C34BD5018CBC0925AC4096E15A0C99F591D5F  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.200-20251216.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.200-20251216.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.200-20251216.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.200-20251216.iso.sig securityonion-2.4.200-20251216.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 15 Dec 2025 05:24:11 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
