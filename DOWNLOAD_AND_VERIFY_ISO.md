### 3.3.0-20260908 ISO image released on 2026/07/29


### Download and Verify

3.3.0-20260908 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.3.0-20260908.iso
 
MD5: 5A2C42D0083F2D7B4DC2178C30EBC05F  
SHA1: 505220A8A3315AFEE601C13772996018425CCD29  
SHA256: 6EB8401296A1D051FEC558C520D2D4AB1912A72D351A2426FBF8C87FEE2BA844  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.3.0-20260908.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.3.0-20260908.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.3.0-20260908.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.3.0-20260908.iso.sig securityonion-3.3.0-20260908.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 08 Sep 2026 10:07:12 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
