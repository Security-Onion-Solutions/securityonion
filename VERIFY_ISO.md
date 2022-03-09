### 2.3.110-20220309 ISO image built on 2022/03/09



### Download and Verify

2.3.110-20220309 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220309.iso

MD5: 537564F8B56633E2D46E5E7C4E2BF18A  
SHA1: 1E1B42EDB711AC8B5963B3460056770B91AE6BFC  
SHA256: 4D73E5BE578DA43DCFD3C1B5F9AF07A7980D8DF90ACDDFEF6CEA177F872EECA0 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220309.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220309.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220309.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.110-20220309.iso.sig securityonion-2.3.110-20220309.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 09 Mar 2022 10:20:47 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
