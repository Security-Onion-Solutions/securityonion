### 2.3.60-CURATORAUTH ISO image built on 2021/07/19



### Download and Verify

2.3.60-CURATORAUTH ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.60-CURATORAUTH.iso

MD5: 953DD42AB3A3560BB35F4E9F69212AE3  
SHA1: 5D18B98B19FD7F8C799E88FC28ABC46990FC6B9B  
SHA256: E26F43F969241985DC74915842492F876EC7B8CBAF5F2F52405554E7C92408C2 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60-CURATORAUTH.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.60-CURATORAUTH.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.60-CURATORAUTH.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.60-CURATORAUTH.iso.sig securityonion-2.3.60-CURATORAUTH.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 19 Jul 2021 01:25:34 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
