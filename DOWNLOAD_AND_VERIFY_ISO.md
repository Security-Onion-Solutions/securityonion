### 2.4.30-20231228 ISO image released on 2024/01/02


### Download and Verify

2.4.30-20231228 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231228.iso
 
MD5: DBD47645CD6FA8358C51D8753046FB54  
SHA1: 2494091065434ACB028F71444A5D16E8F8A11EDF  
SHA256: 3345AE1DC58AC7F29D82E60D9A36CDF8DE19B7DFF999D8C4F89C7BD36AEE7F1D  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231228.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.30-20231228.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.30-20231228.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.30-20231228.iso.sig securityonion-2.4.30-20231228.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 28 Dec 2023 10:08:31 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
