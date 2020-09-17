### 2.2.0-rc3 ISO image built on 2020/09/17

### Download and Verify

2.2.0-rc3 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.2.0-rc3.iso

MD5: 051883501C905653ACBCEC513C294778  
SHA1: 0A66F6636F53B268E7FFB743A3136AC5CC3E0E96  
SHA256: 5A9F303954AF1B1D271CE526E5DCBFC28F3FFC0621B291A29F0F7F2E8EB11C43 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.2.0-rc3.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.2.0-rc3.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.2.0-rc3.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.2.0-rc3.iso.sig securityonion-2.2.0-rc3.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 17 Sep 2020 10:05:27 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.2/installation.html
