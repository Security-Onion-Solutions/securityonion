### 2.3.100-20220301 ISO image built on 2022/03/01



### Download and Verify

2.3.100-20220301 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220301.iso

MD5: 53A992D6321B7C33440219BAD9157769  
SHA1: D730157F4847EB91393CF0C1A22410708312F605  
SHA256: F6C0E55968ED1F0AA35CB9E1F7FF5BEB27673638A4F2223302B301360BC401A1 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220301.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.100-20220301.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.100-20220301.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.100-20220301.iso.sig securityonion-2.3.100-20220301.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 01 Mar 2022 03:14:02 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
