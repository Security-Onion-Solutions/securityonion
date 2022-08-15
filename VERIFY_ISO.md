### 2.3.140-20220812 ISO image built on 2022/08/12



### Download and Verify

2.3.140-20220812 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220812.iso

MD5: 13D4A5D663B5A36D045B980E5F33E6BC  
SHA1: 85DC36B7E96575259DFD080BC860F6508D5F5899  
SHA256: DE5D0F82732B81456180AA40C124E5C82688611941EEAF03D85986806631588C 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220812.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220812.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220812.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.140-20220812.iso.sig securityonion-2.3.140-20220812.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 12 Aug 2022 03:59:11 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
