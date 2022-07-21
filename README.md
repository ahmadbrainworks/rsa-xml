## RSA XML Encrypter/Decrypter


#### Summary

rsa-xml is a library for encrypting/decrypting data using RSA key values that are in xml format.


#### Usage

###### encryption
``` rust

use rsa_xml{XmlRSA};

let rsa_xml = XmlRSA{
    public_key: "public key file path",
    private_key: "private key file path"
    }
let encrypted = XmlRSA.ecnrypt("data"); // plaintext data to encrypt
println!("{}", encrypted);



```


###### decryption
``` rust

use rsa_xml{XmlRSA};

let rsa_xml = XmlRSA{
    public_key: "public key file path",
    private_key: "private key file path"
    }
let decrypted = XmlRSA.denrypt("data"); // encrypted data to decrypt
println!("{}", decrypted);



```
