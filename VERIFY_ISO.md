### 2.3.280-20231128 ISO image built on 2023/11/28



### Download and Verify

2.3.280-20231128 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.280-20231128.iso

MD5: 0BC68BD73547B7E2FBA6F53BEC174590  
SHA1: 1D33C565D37772FE7A3C3FE3ECB05FC1AC1EBFF1  
SHA256: ADBD9DC9E1B266B18E0FDBDF084073EF926C565041858060D283CDAEF021EE11 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.280-20231128.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.280-20231128.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.280-20231128.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.280-20231128.iso.sig securityonion-2.3.280-20231128.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 27 Nov 2023 05:09:34 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
