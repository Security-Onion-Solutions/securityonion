### 2.3.61-STENODOCKER ISO image built on 2021/07/26



### Download and Verify

2.3.61-STENODOCKER ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.61-STENODOCKER.iso

MD5: 10815F1F816E75BF15F331B39CB5EBEC  
SHA1: 2D4F4ACA6FBA35563D76C1296A6A774FF73D67FD  
SHA256: D9C927C07A2B29C0BD93B1349EB750D4E3CF7F553A14D3EF90593BA660936821 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-STENODOCKER.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-STENODOCKER.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.61-STENODOCKER.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.61-STENODOCKER.iso.sig securityonion-2.3.61-STENODOCKER.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 26 Jul 2021 04:34:58 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
