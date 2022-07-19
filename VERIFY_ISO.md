### 2.3.140-20220719 ISO image built on 2022/07/19



### Download and Verify

2.3.140-20220719 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220719.iso

MD5: 68768DF9861B93BB8CC9637C80239803  
SHA1: F15421C045227B334C7044E5F7F309A2BC7AEB19  
SHA256: 4736E3E80E28EFBAB1923C121A3F78DBDBCBBBF65D715924A88B2E96EB3C6093 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220719.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.140-20220719.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.140-20220719.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.140-20220719.iso.sig securityonion-2.3.140-20220719.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 19 Jul 2022 02:00:29 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
