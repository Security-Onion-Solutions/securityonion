### 2.0.2-rc1 ISO image built on 2020/07/23

### Download and Verify

2.0.2-rc1 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.0.2-rc1.iso

MD5: DC991385818DB7A4242F4BF7045D1250  
SHA1: 0BD458F01F10B324DF90F95201CC33B9DEBEAFA3  
SHA256: BE851E5FB1952942A9C10F6563DF6EF93381D734FDFD7E05FFAC77A5064F781A  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.0.2-rc1.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.0.2-rc1.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.0.2-rc1.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.0.2-rc1.iso.sig securityonion-2.0.2-rc1.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 23 Jul 2020 10:38:04 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.0/installation.html
