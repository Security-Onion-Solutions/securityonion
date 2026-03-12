### 2.4.211-20260312 ISO image released on 2026/03/02


### Download and Verify

2.4.211-20260312 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.211-20260312.iso
 
MD5: 7082210AE9FF4D2634D71EAD4DC8F7A3  
SHA1: F76E08C47FD786624B2385B4235A3D61A4C3E9DC  
SHA256: CE6E61788DFC492E4897EEDC139D698B2EDBEB6B631DE0043F66E94AF8A0FF4E  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.211-20260312.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.211-20260312.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.211-20260312.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.211-20260312.iso.sig securityonion-2.4.211-20260312.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 11 Mar 2026 03:05:09 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
