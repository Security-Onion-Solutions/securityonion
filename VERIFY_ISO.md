### 2.3.61 ISO image built on 2021/07/22



### Download and Verify

2.3.61 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.61.iso

MD5: 538F29F3AB57087FC879108FFC81447C  
SHA1: C2239206572CBEB697CFA2A4850A16A54BF5FB0D  
SHA256: F5035361B63D1EE8D87CE7B0D8333E521A44453274785B62630CAC76C1BEA929 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.61.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.61.iso.sig securityonion-2.3.61.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 22 Jul 2021 10:28:58 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
