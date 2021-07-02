### 2.3.60-ECSFIX ISO image built on 2021/07/02



### Download and Verify

2.3.60-ECSFIX ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.60-ECSFIX.iso

MD5: BCD2C449BD3B65D96A0D1E479C0414F9  
SHA1: 18FB8F33C19980992B291E5A7EC23D5E13853933  
SHA256: AD3B750E7FC4CA0D58946D8FEB703AE9B01508E314967566B06CFE5D8A8086E9 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60-ECSFIX.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60-ECSFIX.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.60-ECSFIX.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.60-ECSFIX.iso.sig securityonion-2.3.60-ECSFIX.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 02 Jul 2021 10:15:04 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
