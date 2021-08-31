### 2.3.70-WAZUH ISO image built on 2021/08/23



### Download and Verify

2.3.70-WAZUH ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.70-WAZUH.iso

MD5: CEDEF3C38089896C252F9E3C75F7CB15  
SHA1: FB420115C72DABDEB87C8B27F26E862C94628057  
SHA256: CC3E75A97163E9CD255DA0D9C3EB11922FA045651827F291025398943C1BC230 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-WAZUH.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-WAZUH.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.70-WAZUH.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.70-WAZUH.iso.sig securityonion-2.3.70-WAZUH.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 30 Aug 2021 06:13:14 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
