### 2.3.220-20230301 ISO image built on 2023/03/01



### Download and Verify

2.3.220-20230301 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.220-20230301.iso

MD5: A3965CF8E6D9B0658862D0254829720D  
SHA1: A09E8BE863A109CE556792B968A139600E71D89E  
SHA256: B663B69ACF82EAF5820081039104EEDDE80E3D08F094A0DB3A18C7BCCFE8C162 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.220-20230301.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.220-20230301.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.220-20230301.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.220-20230301.iso.sig securityonion-2.3.220-20230301.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 01 Mar 2023 11:08:31 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
