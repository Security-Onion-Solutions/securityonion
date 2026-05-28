### 3.1.0-20260528 ISO image released on 2026/05/28


### Download and Verify

3.1.0-20260528 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.1.0-20260528.iso
 
MD5: 9D6FF58DEEE24089D722C73169765B3E  
SHA1: 2B8B816B6CEC3B7F96B3C5E040EBF502DD2C412F  
SHA256: 62FAB57E247C843D6A04F0796D8162C732B65D82FC3E4A59D087135B9FD32912  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.1.0-20260528.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.1.0-20260528.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.1.0-20260528.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.1.0-20260528.iso.sig securityonion-3.1.0-20260528.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 27 May 2026 03:03:59 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
