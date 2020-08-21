### 2.1.0-rc2 ISO image built on 2020/08/20

### Download and Verify

2.1.0-rc1 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.1.0-rc2.iso

MD5: C0E543D57D720BB6DF9432C5EE7F8C74  
SHA1: 79E72A7312ADEB41EC8F580A5F5FFC9C7E7E08BE  
SHA256: 4268AE058235BA945151A01F981BE439768750A86515B9204BFF5BC634793374  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.1.0-rc2.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.1.0-rc2.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.1.0-rc2.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.1.0-rc2.iso.sig securityonion-2.1.0-rc2.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 21 Aug 2020 01:09:22 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.1/installation.html
