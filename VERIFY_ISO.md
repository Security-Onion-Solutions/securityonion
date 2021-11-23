### 2.3.90-WAZUH ISO image built on 2021/11/23



### Download and Verify

2.3.90-WAZUH ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.90-WAZUH.iso

MD5: B7141C8627CDB45F4A8741B2ADE4A9F3  
SHA1: 16087B385CA651659EC98F139AFDF90922430FB6  
SHA256: 667AF11BBCFE3248AF59E45043703B55A543E059899AE387FF55EB8077304F04 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-WAZUH.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.90-WAZUH.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.90-WAZUH.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.90-WAZUH.iso.sig securityonion-2.3.90-WAZUH.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 23 Nov 2021 03:19:08 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
