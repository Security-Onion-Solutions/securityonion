### 2.3.250-20230519 ISO image built on 2023/05/19



### Download and Verify

2.3.250-20230519 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.250-20230519.iso

MD5: EBECF635FB8CFDDD5C0559D01C14E215  
SHA1: 1C2BD45D080D6D99FD84C120827EA39817FCB078  
SHA256: 748E9740077BCCAFDC67D15BA2D6A4B0539A29E4527715973E5BDDE5DCF565AD 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.250-20230519.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.250-20230519.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.250-20230519.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.250-20230519.iso.sig securityonion-2.3.250-20230519.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sat 20 May 2023 09:16:02 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
