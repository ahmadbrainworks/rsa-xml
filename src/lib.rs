mod encryption;
// mod converter;
use crate::encryption::{encrypt as rsa_encryption, decrypt as rsa_decryption};


pub struct XmlRSA<'a> {
    pub private_key: &'a str,
    pub public_key: &'a str,
}

impl<'a> XmlRSA<'a> {
    pub fn encrypt(&self, data: &str) -> Result<String, String>{
       return Ok(rsa_encryption(self.public_key, data).unwrap());

    }

    pub fn decrypt(&self, data: &str) -> Result<String, String>{
        return Ok(rsa_decryption(self.private_key, data).unwrap());
    } 
        
}    
    
