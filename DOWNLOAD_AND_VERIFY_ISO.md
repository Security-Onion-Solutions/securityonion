### 2.4.10-20230821 ISO image released on 2023/08/21



### Download and Verify

2.4.10-20230821 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.10-20230821.iso
 
MD5: 353EB36F807DC947F08F79B3DCFA420E  
SHA1: B25E3BEDB81BBEF319DC710267E6D78422F39C56  
SHA256: 3D369E92FEB65D14E1A981E99FA223DA52C92057A037C243AD6332B6B9A6D9BC  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.10-20230821.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.10-20230821.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.10-20230821.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.10-20230821.iso.sig securityonion-2.4.10-20230821.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 21 Aug 2023 09:47:50 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
