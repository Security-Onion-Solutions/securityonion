### 2.4.50-20240220 ISO image released on 2024/02/20


### Download and Verify

2.4.50-20240220 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.50-20240220.iso
 
MD5: BCA6476EF1BF79773D8EFB11700FDE8E  
SHA1: 9FF0A304AA368BCD2EF2BE89AD47E65650241927  
SHA256: 49D7695EFFF6F3C4840079BF564F3191B585639816ADE98672A38017F25E9570  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.50-20240220.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.50-20240220.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.50-20240220.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.50-20240220.iso.sig securityonion-2.4.50-20240220.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 16 Feb 2024 11:36:25 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
