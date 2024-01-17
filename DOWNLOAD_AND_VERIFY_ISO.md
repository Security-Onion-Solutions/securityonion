### 2.4.40-20240116 ISO image released on 2024/01/17


### Download and Verify

2.4.40-20240116 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.40-20240116.iso
 
MD5: AC55D027B663F3CE0878FEBDAD9DD78B  
SHA1: C2B51723B17F3DC843CC493EB80E93B123E3A3E1  
SHA256: C5F135FCF45A836BBFF58C231F95E1EA0CD894898322187AD5FBFCD24BC2F123  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.40-20240116.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.40-20240116.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.40-20240116.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.40-20240116.iso.sig securityonion-2.4.40-20240116.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Tue 16 Jan 2024 07:34:40 PM EST using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
