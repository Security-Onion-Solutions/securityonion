### 3.1.0-20260521 ISO image released on 2026/05/21


### Download and Verify

3.1.0-20260521 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.1.0-20260521.iso
 
MD5: A853BC118639ABCE1795D6E313BFFBDE  
SHA1: FCA615AD6E31710B33AE5870FEF447861FDB3B8F  
SHA256: CE2A5947274D9ED2C5068A1FD46B64C4FEF70445EA9B61A98DD3621781329F2C  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.1.0-20260521.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.1.0-20260521.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.1.0-20260521.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.1.0-20260521.iso.sig securityonion-3.1.0-20260521.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 21 May 2026 11:10:01 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
