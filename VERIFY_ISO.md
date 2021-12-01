### 2.3.90-AIRGAPFIX ISO image built on 2021/12/01



### Download and Verify

2.3.90-AIRGAPFIX ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90-AIRGAPFIX.iso

MD5: A87EEF66FEB2ED6E20ABD4ADDA4899C6  
SHA1: D1AD74D1481E9FF6F1A79D27DC569DA6749EC54B  
SHA256: E4FC40340357B098E881F13BC4960AA8CB5F5AC73C05E077C993078ED7F46D59 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-AIRGAPFIX.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-AIRGAPFIX.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90-AIRGAPFIX.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90-AIRGAPFIX.iso.sig securityonion-2.3.90-AIRGAPFIX.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 01 Dec 2021 11:07:16 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
