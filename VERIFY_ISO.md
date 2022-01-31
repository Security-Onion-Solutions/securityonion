### 2.3.100-20220131 ISO image built on 2022/01/31



### Download and Verify

2.3.100-20220131 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220131.iso

MD5: 9B50774532B77A10E2F52A3F0492A780  
SHA1: 3C50D2EF4AFFFA8929492C2FC3842FF3EEE0EA5F  
SHA256: CDCBEE6B1FDFB4CAF6C9F80CCADC161366EC337746E8394BF4454FAA2FC11AA1 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220131.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220131.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220131.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.100-20220131.iso.sig securityonion-2.3.100-20220131.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 31 Jan 2022 11:41:30 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
