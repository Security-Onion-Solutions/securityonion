### 2.3.290-20240229 ISO image built on 2024/02/29



### Download and Verify

2.3.290-20240229 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.290-20240229.iso

MD5: D2A7BBDA25F311B7944A95655CC439CE  
SHA1: BAD2A67119C6F73B6472E1A31B9C157A60A074B5  
SHA256: FD611421C3B41BA267BA7A57B8FAFB29B0B59435D0A796D686C0D3BDD36AFF7D 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.290-20240229.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.290-20240229.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.290-20240229.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.290-20240229.iso.sig securityonion-2.3.290-20240229.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 28 Feb 2024 04:11:05 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
