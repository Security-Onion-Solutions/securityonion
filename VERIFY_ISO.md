### 2.3.1 ISO image built on 2020/10/22

### Download and Verify

2.3.1 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.1.iso

MD5: EF2DEBCCBAE0B0BCCC906552B5FF918A
SHA1: 16AFCACB102BD217A038044D64E7A86DA351640E  
SHA256: 7125F90B6323179D0D29F5745681BE995BD2615E64FA1E0046D94888A72C539E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.1.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.1.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.1.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.1.iso.sig securityonion-2.3.1.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 22 Oct 2020 10:34:27 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
