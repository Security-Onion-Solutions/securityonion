### 2.3.60 ISO image built on 2021/04/27


### Download and Verify

2.3.60 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.60.iso

MD5: 77AF432E46B6DE97C17827EB0E6B1ECD  
SHA1: 0098C0383D9CA5FCC35F0320F22C3A7F2A171A3E  
SHA256: 10869C21A47A162F347069F52DC203C843672A561C2AC303776525FE8A1F28C7 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.60.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.60.iso.sig securityonion-2.3.60.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 30 Jun 2021 10:00:50 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
