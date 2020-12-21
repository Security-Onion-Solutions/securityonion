### 2.3.20 ISO image built on 2020/11/19

### Download and Verify

2.3.20 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.20.iso

MD5: E348FA65A46FD3FBA0D574D9C1A0582D  
SHA1: 4A6E6D4E0B31ECA1B72E642E3DB2C186B59009D6  
SHA256: 25DE77097903640771533FA13094D0720A032B70223875F8C77A92F5C44CA687 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.20.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.20.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.20.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.20.iso.sig securityonion-2.3.20.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sun 20 Dec 2020 11:11:28 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
