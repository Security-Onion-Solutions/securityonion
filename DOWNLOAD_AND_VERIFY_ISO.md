### 3.4.0-20261101 ISO image released on 2026/11/01


### Download and Verify

3.4.0-20261101 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.4.0-20261101.iso
 
MD5: 486097F2A33F0553BBBF6B7664656E18  
SHA1: D6E8B100FFF8BD04DC0FC95AF9D89F54166481D1  
SHA256: F65F190E5BE0BD944EA859A48D5031F75A2061FAD57D11C07B190A680CC62E9C  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.4.0-20261101.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.4.0-20261101.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.4.0-20261101.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.4.0-20261101.iso.sig securityonion-3.4.0-20261101.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 29 Oct 2026 06:20:38 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
