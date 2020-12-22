### 2.3.21 ISO image built on 2020/12/21

### Download and Verify

2.3.21 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.21.iso

MD5: 7B8BC5B241B7220C011215BCE852FF78  
SHA1: 541C9689D8F8E8D3F25E169ED34A3F683851975B  
SHA256: 7647FD67BA6AC85CCB1308789FFF7DAB19A841621FDA9AE41B89A0A79618F068 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.21.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.21.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.21.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.21.iso.sig securityonion-2.3.21.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 21 Dec 2020 06:27:53 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
