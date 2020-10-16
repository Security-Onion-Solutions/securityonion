### 2.3.0 ISO image built on 2020/10/15

### Download and Verify

2.3.0 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.0.iso

MD5: E05B220E4FD7C054DF5C50906EE1375B
SHA1: 55E93C6EAB140AB4A0F07873CC871EBFDC699CD6  
SHA256: 57B96A6E0951143E123BFC0CD0404F7466776E69F3C115F5A0444C0C6D5A6E32 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.0.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.0.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.0.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.0.iso.sig securityonion-2.3.0.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 15 Oct 2020 08:06:28 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
