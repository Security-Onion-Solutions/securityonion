### 2.4.100-20240829 ISO image released on 2024/08/29


### Download and Verify

2.4.100-20240829 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.100-20240829.iso
 
MD5: 377586C143FABD662DB414DEA49D46B7  
SHA1: 69D4B94522789AF47075A9FF1354B069679AC366  
SHA256: 52FBA5C8762B8DCF2945AD2837B3A19E63ADCC209AB510D7FD0F86AE713AA153  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.100-20240829.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.100-20240829.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.100-20240829.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.100-20240829.iso.sig securityonion-2.4.100-20240829.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 29 Aug 2024 12:02:55 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
