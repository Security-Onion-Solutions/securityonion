### 2.3.220-20230224 ISO image built on 2023/02/24



### Download and Verify

2.3.220-20230224 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.220-20230224.iso

MD5: 74CDCE07BC5787567E07C1CAC64DC381  
SHA1: 8DA0E8541C46CBDCFA0FB9B60F3C95D027D4BB37  
SHA256: E5EDB011693AC33C40CAB483400F72FAF9615053867FD9C80DDD1AACAD9100B3 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.220-20230224.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.220-20230224.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.220-20230224.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.220-20230224.iso.sig securityonion-2.3.220-20230224.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 24 Feb 2023 02:32:08 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
