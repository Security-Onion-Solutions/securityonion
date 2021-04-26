### 2.3.50 ISO image built on 2021/04/25

### Download and Verify

2.3.50 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.50.iso

MD5: 8B74AF6F29DB156E3D467B25E1D46449  
SHA1: 99A0A96C5F206471E4F1D26A8A2D577A8ECDAED5  
SHA256: CA0EE3793FC1356FB5C50D36107FA3BB39DE6C40EBE6C7C90075D5C189BB3083 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.50.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.50.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.50.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.50.iso.sig securityonion-2.3.50.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sun 25 Apr 2021 01:01:35 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
