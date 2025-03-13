### 2.4.130-20250311 ISO image released on 2025/03/11


### Download and Verify

2.4.130-20250311 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.130-20250311.iso
 
MD5: 4641CA710570CCE18CD7D50653373DC0  
SHA1: 786EF73F7945FDD80126C9AE00BDD29E58743715  
SHA256: 48C7A042F20C46B8087BAE0F971696DADE9F9364D52F416718245C16E7CCB977  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.130-20250311.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.130-20250311.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.130-20250311.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.130-20250311.iso.sig securityonion-2.4.130-20250311.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 10 Mar 2025 06:30:49 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
