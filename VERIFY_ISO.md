### 2.3.180-20221014 ISO image built on 2022/10/14



### Download and Verify

2.3.180-20221014 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.180-20221014.iso

MD5: 83FFF252C70A286860E02B5F2ACE5F16  
SHA1: 27B50B2ECE5B59C2FFF4E60FD10E72589B6D914E  
SHA256: 9AE4109C12F3CF77ACD6A9FCFD89CD0AEB4F18C1B72DB7ACE451F9EADA448273 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.180-20221014.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.180-20221014.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.180-20221014.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.180-20221014.iso.sig securityonion-2.3.180-20221014.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 14 Oct 2022 09:50:51 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
