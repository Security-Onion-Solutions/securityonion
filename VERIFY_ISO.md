### 2.3.70-GRAFANA ISO image built on 2021/08/23



### Download and Verify

2.3.70-GRAFANA ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.70-GRAFANA.iso

MD5: A16683FC8F2151C290E359FC6066B1F2  
SHA1: A93329C103CCCE665968F246163FBE5D41EF0510  
SHA256: 3ED0177CADF203324363916AA240A10C58DC3E9044A9ADE173A80674701A50A3 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-GRAFANA.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-GRAFANA.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.70-GRAFANA.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.70-GRAFANA.iso.sig securityonion-2.3.70-GRAFANA.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 23 Aug 2021 01:43:00 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
