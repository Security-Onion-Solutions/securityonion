### 2.3.182-20221109 ISO image built on 2022/11/09



### Download and Verify

2.3.182-20221109 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.182-20221109.iso

MD5: E472D5A7C64662435F84FD56491D8967  
SHA1: D2069317553AF0A1FB4FB6FE15583FF4E8CB2973  
SHA256: A074EB38B88C0A00BDFD7FB75B4ECB7C46CB0B4CC993CAB81EFDC708B0075D2C 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.182-20221109.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.182-20221109.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.182-20221109.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.182-20221109.iso.sig securityonion-2.3.182-20221109.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 09 Nov 2022 07:30:32 AM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
