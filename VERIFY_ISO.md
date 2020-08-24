### 2.1.0-rc2 ISO image built on 2020/08/23

### Download and Verify

2.1.0-rc2 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.1.0-rc2.iso

MD5: 9EAE772B64F5B3934C0DB7913E38D6D4  
SHA1: D0D347AE30564871DE81203C0CE53B950F8732CE  
SHA256: 888AC7758C975FAA0A7267E5EFCB082164AC7AC8DCB3B370C06BA0B8493DAC44  

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
gpg: Signature made Sun 23 Aug 2020 04:37:00 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.1/installation.html
