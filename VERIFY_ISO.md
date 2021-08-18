### 2.3.70 ISO image built on 2021/08/17



### Download and Verify

2.3.70 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.70.iso

MD5: F048FABC7FD2D0E1A8B02381F115D1E0  
SHA1: DF6D20FEF13CDC1B19309D2A1178D6E5D25FDA6F  
SHA256: B193FFD7EE69958A8E257117149DCFB2125C5772FBFA6003AD80FD1CC129E571 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.70.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.70.iso.sig securityonion-2.3.70.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 17 Aug 2021 10:52:17 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
