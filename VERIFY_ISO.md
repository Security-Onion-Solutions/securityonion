### 2.3.40 ISO image built on 2021/03/22

### Download and Verify

2.3.40 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.40.iso

MD5: FB72C0675F262A714B287BB33CE82504  
SHA1: E8F5A9AA23990DF794611F9A178D88414F5DA81C  
SHA256: DB125D6E770F75C3FD35ABE3F8A8B21454B7A7618C2B446D11B6AC8574601070 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.40.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.40.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.40.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.40.iso.sig securityonion-2.3.40.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 22 Mar 2021 09:35:50 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
