### 2.4.10-20230815 ISO image released on 2023/08/15



### Download and Verify

2.4.10-20230815 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.10-20230815.iso
 
MD5: 97AEC929FB1FC22F106C0C93E3476FAB  
SHA1: 78AF37FD19FDC34BA324C1A661632D19D1F2284A  
SHA256: D04BA45D1664FC3CF7EA2188CB7E570642F6390C3959B4AFBB8222A853859394  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.10-20230815.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.10-20230815.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.10-20230815.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.10-20230815.iso.sig securityonion-2.4.10-20230815.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sun 13 Aug 2023 05:30:29 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
