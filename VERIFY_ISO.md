### 2.3.130-20220606 ISO image built on 2022/06/06



### Download and Verify

2.3.130-20220606 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.130-20220606.iso

MD5: 62DA0E2EE1B0BE37CEA914F4C95CB074  
SHA1: D63CD6BBCA65D0CC59345F1639293E25A7365C93  
SHA256: B40252571B3D86E3BB5C3B21510BA657F48B1EE691BD6D60D5E1133514E3CC1A 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.130-20220606.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.130-20220606.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.130-20220606.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.130-20220606.iso.sig securityonion-2.3.130-20220606.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 06 Jun 2022 06:20:46 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
