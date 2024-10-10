### 2.4.110-20241010 ISO image released on 2024/10/10


### Download and Verify

2.4.110-20241010 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.110-20241010.iso
 
MD5: A8003DEBC4510D538F06238D9DBB86C0  
SHA1: 441DE90A192C8FE8BEBAB9ACE1A3CC18F71A2B1F  
SHA256: B087A0D12FC2CA3CCD02BD52E52421F4F60DC09BF826337A057E05A04D114CCE  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.110-20241010.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.110-20241010.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.110-20241010.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.110-20241010.iso.sig securityonion-2.4.110-20241010.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Thu 10 Oct 2024 07:05:30 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

If it fails to verify, try downloading again. If it still fails to verify, try downloading from another computer or another network.

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
