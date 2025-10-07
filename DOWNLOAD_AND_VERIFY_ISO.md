### 2.4.180-20250916 ISO image released on 2025/09/17


### Download and Verify

2.4.180-20250916 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.180-20250916.iso
 
MD5: DE93880E38DE4BE45D05A41E1745CB1F  
SHA1: AEA6948911E50A4A38E8729E0E965C565402E3FC  
SHA256: C9BD8CA071E43B048ABF9ED145B87935CB1D4BB839B2244A06FAD1BBA8EAC84A  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.180-20250916.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.180-20250916.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.180-20250916.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.180-20250916.iso.sig securityonion-2.4.180-20250916.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 16 Sep 2025 06:30:19 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
