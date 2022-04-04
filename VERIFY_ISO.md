### 2.3.110-20220401 ISO image built on 2022/04/04



### Download and Verify

2.3.110-20220401 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220401.iso

MD5: 17625039D4ED23EC217589A1681C4FDA  
SHA1: 8244A7BE12F27E71721ADC699950BB27C5C03BF2  
SHA256: 76C135C3FDA8A28C13A142B944BE72E67192AC7C4BC85838230EFF45E8978BD1 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220401.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220401.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220401.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.110-20220401.iso.sig securityonion-2.3.110-20220401.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Mon 04 Apr 2022 02:08:59 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
