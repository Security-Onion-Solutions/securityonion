### 2.4.30-20231204 ISO image released on 2023/12/06



### Download and Verify

2.4.30-20231204 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231204.iso
 
MD5: 596A164241D0C62AEBBE23D7883F505E  
SHA1: 139FE16DC3B13B1F1A748EE57BC2C5FEBADAEB07  
SHA256: D5730F9952F5AC6DF06D4E02A9EF5C43B16AC85D8072C6D60AEFF03281122C71  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231204.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231204.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231204.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.30-20231204.iso.sig securityonion-2.4.30-20231204.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 05 Dec 2023 11:46:42 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
