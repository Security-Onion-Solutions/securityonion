### 2.3.30 ISO image built on 2021/03/01

### Download and Verify

2.3.30 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.30.iso

MD5: 7716A56E0F46FA29422B07B30235417B  
SHA1: D01C26E4391C80FF690384C1DB77550EA4C1E239  
SHA256: 3BB0CE7F3F84A0D26B00EAF30F7AEB42A3B5C7E9D8E3BA7E160577B1FA3830F6 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.30.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.30.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.30.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.30.iso.sig securityonion-2.3.30.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 01 Mar 2021 10:23:05 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
