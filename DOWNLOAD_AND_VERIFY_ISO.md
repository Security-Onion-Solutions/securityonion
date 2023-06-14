### 2.4.2-20230531 ISO image built on 2023/05/31



### Download and Verify

2.4.2-20230531 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.2-20230531.iso

MD5: EB861EFB7F7DA6FB418075B4C452E4EB  
SHA1: 479A72DBB0633CB23608122F7200A24E2C3C3128  
SHA256: B69C1AE4C576BBBC37F4B87C2A8379903421E65B2C4F24C90FABB0EAD6F0471B 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.2-20230531.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.2-20230531.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.2-20230531.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.2-20230531.iso.sig securityonion-2.4.2-20230531.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 31 May 2023 05:01:41 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
