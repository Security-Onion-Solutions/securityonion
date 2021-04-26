### 2.3.50 ISO image built on 2021/04/26

### Download and Verify

2.3.50 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.50.iso

MD5: 1FF774520D3B1323D83BBF90BD9EFACE  
SHA1: 0F323335459A11850B68BB82E062F581225303EE  
SHA256: 2AACD535E0EACE17E8DC7B560353D43111A287C59C23827612B720D742DFD994 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.50.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.50.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.50.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.50.iso.sig securityonion-2.3.50.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 26 Apr 2021 03:54:51 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
