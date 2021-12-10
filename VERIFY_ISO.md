### 2.3.90-20211210 ISO image built on 2021/12/10



### Download and Verify

2.3.90-20211210 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211210.iso

MD5: 512C13089060EE17BC3FA275D62152DC  
SHA1: A70D3A3C4B74AD2EE9B1353BDE7E5DD327248511  
SHA256: 271DA7617FBA3549B1E496C60E9AD743B13CC8D0468DF3F7AC9A76B6D496D212 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211210.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-20211210.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90-20211210.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90-20211210.iso.sig securityonion-2.3.90-20211210.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 10 Dec 2021 02:52:08 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
