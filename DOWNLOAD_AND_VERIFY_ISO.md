### 2.4.20-20231012 ISO image released on 2023/10/12



### Download and Verify

2.4.20-20231012 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.20-20231012.iso
 
MD5: 7D6ACA843068BA9432B3FF63BFD1EF0F  
SHA1: BEF2B906066A1B04921DF0B80E7FDD4BC8ECED5C  
SHA256: 5D511D50F11666C69AE12435A47B9A2D30CB3CC88F8D38DC58A5BC0ECADF1BF5  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.20-20231012.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.20-20231012.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.20-20231012.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.20-20231012.iso.sig securityonion-2.4.20-20231012.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 12 Oct 2023 01:28:32 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
