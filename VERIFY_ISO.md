### 2.3.80 ISO image built on 2021/09/27



### Download and Verify

2.3.80 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.80.iso

MD5: 24F38563860416F4A8ABE18746913E14  
SHA1: F923C005F54EA2A17AB225ADA0DA46042707AAD9  
SHA256: 8E95D10AF664D9A406C168EC421D943CB23F0D0C1813C6C2DBA9B4E131984018 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.80.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.80.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.80.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.80.iso.sig securityonion-2.3.80.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 27 Sep 2021 08:55:01 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
