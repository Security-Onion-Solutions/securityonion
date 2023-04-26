### 2.3.240-20230426 ISO image built on 2023/04/26



### Download and Verify

2.3.240-20230426 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.240-20230426.iso

MD5: 1935B559A9181522E83DA64C0A095A7A  
SHA1: 84A865A8F880036A5F04990CAAC36093744E8CF7  
SHA256: 1CC1173A403EE0CEA05EFB4708E7A4AEA70CEAAF1E3B51B861410F7634A776AF 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.240-20230426.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.240-20230426.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.240-20230426.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.240-20230426.iso.sig securityonion-2.3.240-20230426.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 26 Apr 2023 08:55:32 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
