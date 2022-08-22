### 2.3.150-20220820 ISO image built on 2022/08/12



### Download and Verify

2.3.150-20220820 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.150-20220820.iso

MD5: D2C0B67F19C18F0AB6FD1EC9B1E4034A  
SHA1: F14BF42C6C634BDECA654B169FE6815BB6798F70  
SHA256: 9E37E5CCCBD209486EB79E8F991DE83F64E2208D32E5B56F8E0A6C3933EB42AC 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.150-20220820.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.150-20220820.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.150-20220820.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.150-20220820.iso.sig securityonion-2.3.150-20220820.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Sat 20 Aug 2022 08:07:10 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
