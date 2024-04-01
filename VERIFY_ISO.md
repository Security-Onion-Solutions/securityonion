### 2.3.300-20240401 ISO image built on 2024/04/01



### Download and Verify

2.3.300-20240401 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.300-20240401.iso

MD5: 5CBDA8012D773C5EC362D21C4EA3B7FB  
SHA1: 7A34FAA0E11F09F529FF38EC3239211CD87CB1A7  
SHA256: 123066DAFBF6F2AA0E1924296CFEFE1213002D7760E8797AB74F1FC1D683C6D7 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.300-20240401.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.300-20240401.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.300-20240401.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.300-20240401.iso.sig securityonion-2.3.300-20240401.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 27 Mar 2024 05:09:33 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
