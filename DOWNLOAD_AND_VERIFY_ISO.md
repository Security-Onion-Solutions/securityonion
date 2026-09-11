### 3.3.0-20260911ISO image released on 2026/09/11


### Download and Verify

3.3.0-20260911ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-3.3.0-20260911.iso
 
MD5: 12B18433D3A2198A185892FF79CF638F  
SHA1: 2B3C2E1FA7A78ED1F956E7EDCC12E32593C14EEE  
SHA256: 0938C73B76CE30EC9E4394D312C79EA7CAC721B6818541697279A6221F7D870D  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.3.0-20260911.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/3/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/3/main/sigs/securityonion-3.3.0-20260911.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-3.3.0-20260911.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-3.3.0-20260911.iso.sig securityonion-3.3.0-20260911.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 11 Sep 2026 11:23:56 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://securityonion.net/docs/installation
