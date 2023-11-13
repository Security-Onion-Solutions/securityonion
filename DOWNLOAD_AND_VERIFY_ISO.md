### 2.4.30-20231113 ISO image released on 2023/11/13



### Download and Verify

2.4.30-20231113 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231113.iso
 
MD5: 15EB5A74782E4C2D5663D29E275839F6  
SHA1: BBD4A7D77ADDA94B866F1EFED846A83DDFD34D73  
SHA256: 4509EB8E11DB49C6CD3905C74C5525BDB1F773488002179A846E00DE8E499988  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231113.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231113.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231113.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.30-20231113.iso.sig securityonion-2.4.30-20231113.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 13 Nov 2023 09:23:21 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
