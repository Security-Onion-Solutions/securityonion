### 2.3.110-20220405 ISO image built on 2022/04/05



### Download and Verify

2.3.110-20220405 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220405.iso

MD5: 9CE982FE45DC2957A3A6D376E6DCC048  
SHA1: 10E3FF28A69F9617D4CCD2F5061AA2DC062B8F94  
SHA256: 0C178A422ABF7B61C08728E32CE20A9F9C1EC65807EB67D06F1C23F7D1EA51A7 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220405.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.110-20220405.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.110-20220405.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.110-20220405.iso.sig securityonion-2.3.110-20220405.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 05 Apr 2022 06:37:40 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
