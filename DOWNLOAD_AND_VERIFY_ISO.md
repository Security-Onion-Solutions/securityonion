### 2.4.30-20231121 ISO image released on 2023/11/21



### Download and Verify

2.4.30-20231121 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231121.iso
 
MD5: 09DB0A6B3A75435C855E777272FC03F8  
SHA1: A68868E67A3F86B77E01F54067950757EFD3BA72  
SHA256: B3880C0302D9CDED7C974585B14355544FC9C3279F952EC79FC2BA9AEC7CB749  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231121.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231121.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231121.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.30-20231121.iso.sig securityonion-2.4.30-20231121.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 21 Nov 2023 01:21:38 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
