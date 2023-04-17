### 2.3.230-20230417 ISO image built on 2023/04/17



### Download and Verify

2.3.230-20230417 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.230-20230417.iso

MD5: EBE7E5407AF9AF6F1ADCB9A8E011729B  
SHA1: EC101F5C633D368205F5B756F063308A0BE0466E  
SHA256: CBB9BE490AB44BCC2C8CAB8AAE65288BE130B43927DFA4DFBDD9D95B3564D65F 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.230-20230417.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.230-20230417.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.230-20230417.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.230-20230417.iso.sig securityonion-2.3.230-20230417.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 14 Apr 2023 11:12:57 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
