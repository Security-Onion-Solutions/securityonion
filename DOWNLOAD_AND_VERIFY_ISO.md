### 2.4.5-20230807 ISO image released on 2023/08/07



### Download and Verify

2.4.5-20230807 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.5-20230807.iso
 
MD5: F83FD635025A3A65B380EAFCEB61A92E
SHA1: 5864D4CD520617E3328A3D956CAFCC378A8D2D08
SHA256: D333BAE0DD198DFD80DF59375456D228A4E18A24EDCDB15852CD4CA3F92B69A7

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.5-20230807.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.5-20230807.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.5-20230807.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.5-20230807.iso.sig securityonion-2.4.5-20230807.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sat 05 Aug 2023 10:12:46 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
