### 3.4.0-20261102 ISO image released on 2026/11/02


### Download and Verify

3.4.0-20261102 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.4.0-20261102.iso
 
MD5: FB0380AE996E175D6CC7E7A35D8CC178  
SHA1: D8960F1DA352710BCA209773BF0B3AE8791D0D1B  
SHA256: DFC4C87668836852A328EC7A0B755C8C1511FF0E43D423DEE23047A95F676D99  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.4.0-20261102.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.4.0-20261102.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.4.0-20261102.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.4.0-20261102.iso.sig securityonion-3.4.0-20261102.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sat 31 Oct 2026 09:27:50 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
