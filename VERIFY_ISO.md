### 2.3.70-CURATOR ISO image built on 2021/08/20



### Download and Verify

2.3.70-CURATOR ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.70-CURATOR.iso

MD5: FECB0156F1E3BC9BD1E074FF8C6B2B6D  
SHA1: 38C1AF89C2CFFD7777E4E7A7C8DA1FEC5BB163D5  
SHA256: 38835C6096E859E3FDD1253678312AEC15BD95A08F681B86D84990A4094B48DC 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-CURATOR.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.70-CURATOR.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.70-CURATOR.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.70-CURATOR.iso.sig securityonion-2.3.70-CURATOR.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Fri 20 Aug 2021 11:26:28 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
