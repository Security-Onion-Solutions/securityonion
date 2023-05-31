### 2.4.2-20230531 ISO image built on 2023/05/31



### Download and Verify

2.4.2-20230531 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.2-20230531.iso

MD5: 3BA7D8EF63C6AB7F429363A1A4163BD7  
SHA1: FEA75AA5B0D30B6F8DB1A005F2E9F9EC88D5031A  
SHA256: 5614AA6A6087EBEEA9376D42BEFF61BABE98BEECD74C69213645C6640B5841EB 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.2-20230531.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.2-20230531.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.2-20230531.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.2-20230531.iso.sig securityonion-2.4.2-20230531.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 31 May 2023 02:17:07 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html