### 2.3.260-20230620 ISO image built on 2023/06/20



### Download and Verify

2.3.260-20230620 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.260-20230620.iso

MD5: E09BB9800BAE84E84511516952264F33  
SHA1: DBDDFCE58B87F61F40BCE03840A749D8054B7AF1  
SHA256: 06ED74278587B09167FBAC1E5796B666FC24AD15D06EA3CC36419D07967E06DD 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.260-20230620.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.260-20230620.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.260-20230620.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.260-20230620.iso.sig securityonion-2.3.260-20230620.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 16 Jun 2023 02:58:22 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
