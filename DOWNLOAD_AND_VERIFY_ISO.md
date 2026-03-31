### 3.0.0-20260331 ISO image released on 2026/03/31


### Download and Verify

3.0.0-20260331 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.0.0-20260331.iso
 
MD5: ECD318A1662A6FDE0EF213F5A9BD4B07  
SHA1: E55BE314440CCF3392DC0B06BC5E270B43176D9C  
SHA256: 7FC47405E335CBE5C2B6C51FE7AC60248F35CBE504907B8B5A33822B23F8F4D5  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.0.0-20260331.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.0.0-20260331.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.0.0-20260331.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.0.0-20260331.iso.sig securityonion-3.0.0-20260331.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 30 Mar 2026 06:22:14 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
