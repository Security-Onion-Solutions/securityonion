### 2.4.160-20250625 ISO image released on 2025/06/25


### Download and Verify

2.4.160-20250625 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.160-20250625.iso
 
MD5: 78CF5602EFFAB84174C56AD2826E6E4E  
SHA1: FC7EEC3EC95D97D3337501BAA7CA8CAE7C0E15EA  
SHA256: 0ED965E8BEC80EE16AE90A0F0F96A3046CEF2D92720A587278DDDE3B656C01C2  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.160-20250625.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.160-20250625.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.160-20250625.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.160-20250625.iso.sig securityonion-2.4.160-20250625.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 25 Jun 2025 10:13:33 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
