### 2.0.0-rc1 ISO image built on 2020/07/20

### Download and Verify

2.0.0-rc1 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.0.0-rc1.iso

MD5: 788570E839439C23956581C6145B8689  
SHA1: A87CAF016C989D4DB4D4ED619DF072B708BA28FE  
SHA256: C5AC6419AF40CB98E93C53CE4101E7DE5F51AEE76DB46734191D783503649210  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.0.0-rc1.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.0.0-rc1.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.0.0-rc1.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.0.0-rc1.iso.sig securityonion-2.0.0-rc1.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 20 Jul 2020 03:01:19 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.0/installation.html
