### 2.3.200-20230113 ISO image built on 2023/01/13



### Download and Verify

2.3.200-20230113 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.200-20230113.iso

MD5: 70291FFE925E2751559589E749B12164  
SHA1: EFD3C7BA6F4EF6774F4F18ECD667A13F7FDF5CFF  
SHA256: 7794C1325F9B72856FC2A47691F7E0292CA28976711A18F550163E3B58E7A401 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.200-20230113.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.200-20230113.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.200-20230113.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.200-20230113.iso.sig securityonion-2.3.200-20230113.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 13 Jan 2023 11:11:11 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
