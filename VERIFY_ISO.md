### 2.3.190-20221207 ISO image built on 2022/12/07



### Download and Verify

2.3.190-20221207 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.190-20221207.iso

MD5: 0DBC3718D4FE133E5F4E7BDCA9117F7F  
SHA1: A9B988A293125A0D41482D74397FE747A3701181  
SHA256: E7E2DCA74FEB76249C36CBADB862C69336C745F7835005B9A382D347313AE75E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.190-20221207.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.190-20221207.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.190-20221207.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.190-20221207.iso.sig securityonion-2.3.190-20221207.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 07 Dec 2022 09:44:10 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
