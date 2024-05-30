### 2.4.70-20240529 ISO image released on 2024/05/29


### Download and Verify

2.4.70-20240529 ISO image:  
https://download.securityonion.net/file/securityonion/securityonion-2.4.70-20240529.iso
 
MD5: 8FCCF31C2470D1ABA380AF196B611DEC  
SHA1: EE5E8F8C14819E7A1FE423E6920531A97F39600B  
SHA256: EF5E781D50D50660F452ADC54FD4911296ECBECED7879FA8E04687337CA89BEC  

Signature for ISO image:  
https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.70-20240529.iso.sig

Signing key:  
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS  

For example, here are the steps you can use on most Linux distributions to download and verify our Security Onion ISO image.

Download and import the signing key:  
```
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.4/main/KEYS -O - | gpg --import -  
```

Download the signature file for the ISO:  
```
wget https://github.com/Security-Onion-Solutions/securityonion/raw/2.4/main/sigs/securityonion-2.4.70-20240529.iso.sig
```

Download the ISO image:  
```
wget https://download.securityonion.net/file/securityonion/securityonion-2.4.70-20240529.iso
```

Verify the downloaded ISO image using the signature file:  
```
gpg --verify securityonion-2.4.70-20240529.iso.sig securityonion-2.4.70-20240529.iso
```

The output should show "Good signature" and the Primary key fingerprint should match what's shown below:
```
gpg: Signature made Wed 29 May 2024 11:40:59 AM EDT using RSA key ID FE507013
gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
```

Once you've verified the ISO image, you're ready to proceed to our Installation guide:  
https://docs.securityonion.net/en/2.4/installation.html
