### 2.4.4-20230728 ISO image built on 2023/07/28



### Download and Verify

2.4.4-20230728 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.4-20230728.iso

MD5: F63E76245F3E745B5BDE9E6E647A7CB6  
SHA1: 6CE4E4A3399CD282D4F8592FB19D510388AB3EEA  
SHA256: BF8FEB91B1D94B67C3D4A79D209B068F4A46FEC7C15EEF65B0FCE9851D7E6C9F 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.4-20230728.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.4-20230728.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.4-20230728.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.4-20230728.iso.sig securityonion-2.4.4-20230728.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 11 Jul 2023 06:23:37 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
