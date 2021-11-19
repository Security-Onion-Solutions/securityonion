### 2.3.90 ISO image built on 2021/11/19



### Download and Verify

2.3.90 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90.iso

MD5: 1297FCD812932998DE1273451B303CE3  
SHA1: BF8A377AD1A6B86C5E5268F922380D8973B69D83  
SHA256: 28A47A6EC0794E23B045E5F5631671E78AFE3F08447EC6E5573F72B1B30FDB9E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90.iso.sig securityonion-2.3.90.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 19 Nov 2021 11:53:05 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
