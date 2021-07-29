### 2.3.61-MSEARCH ISO image built on 2021/07/29



### Download and Verify

2.3.61-MSEARCH ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.3.61-MSEARCH.iso

MD5: D38450A6609A1DFF0E19482517B24275  
SHA1: DBCBD8F035FD875DC56307982A2480A62BCAB96D  
SHA256: D7767AA10FE5D655E8502BDC9B8F963C5584DF8F72F26A5A997C1F2277D4F07E 

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-MSEARCH.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-MSEARCH.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.61-MSEARCH.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.3.61-MSEARCH.iso.sig securityonion-2.3.61-MSEARCH.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 28 Jul 2021 05:27:35 PM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.3/installation.html
