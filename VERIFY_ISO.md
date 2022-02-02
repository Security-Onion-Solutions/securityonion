### 2.3.100-20220202 ISO image built on 2022/02/02



### Download and Verify

2.3.100-20220202 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220202.iso

MD5: 170337342118DC32F8C2F687F332CA25  
SHA1: 202235BFE37F1F2E129F5D5DE13173A27A9D8CC0  
SHA256: F902C561D35F5B9DFB2D65BDAE97D30FD9E46F6822AFA36CA9C4043C50864484 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220202.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220202.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220202.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.100-20220202.iso.sig securityonion-2.3.100-20220202.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 02 Feb 2022 12:12:39 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
