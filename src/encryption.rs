use std::fs;
use serde_derive::{Deserialize, Serialize};
use serde_xml_rs::{from_str};
use openssl::bn::BigNum;
use std::convert::AsRef;
use openssl::rsa::Rsa;
use std::sync::Arc;
use openssl::rsa::Padding;

#[derive(Serialize, Deserialize)] 
pub struct RsaKeyValue {
    #[serde(rename = "Modulus")]
    pub modulus: String,

    #[serde(rename = "Exponent")]
    pub exponent: String,

    #[serde(rename = "P")]
    pub p: String,

    #[serde(rename = "Q")]
    pub q: String,

    #[serde(rename = "DP")]
    pub dp: String,

    #[serde(rename = "DQ")]
    pub dq: String,

    #[serde(rename = "InverseQ")]
    pub inverse_q: String,

    #[serde(rename = "D")]
    pub d: String,
}
pub fn encrypt(key: &str, data: &str) -> Result<String, String> {
    let file = fs::read_to_string(key).unwrap();
    let xml_file: RsaKeyValue = from_str(&file).unwrap();
    
    let n = xml_file.modulus;
    let decoded_n = base64::decode(n.as_bytes()).unwrap();
    let e = xml_file.exponent;
    let decoded_e = base64::decode(e.as_bytes()).unwrap();

    let big_e = BigNum::from_slice(&decoded_e).expect("error");
    let big_n = BigNum::from_slice(&decoded_n).expect("error");

    let rsa = Rsa::from_public_components(big_n, big_e).unwrap();

    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

    let _enc = rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1_OAEP).unwrap();
    let buf = Arc::new(buf);
   
   return Ok(base64::encode(buf.clone().as_ref())); 


}

pub fn decrypt(key: &str, data: &str) -> Result<String, String> {

    let file = fs::read_to_string(key).unwrap();
    let xml_file: RsaKeyValue = from_str(&file).unwrap();

    let n = xml_file.modulus;
    let decoded_n = base64::decode(n.as_bytes()).unwrap();

    let e = xml_file.exponent;
    let decoded_e = base64::decode(e.as_bytes()).unwrap();
    
    let p = xml_file.p;
    let decoded_p = base64::decode(p.as_bytes()).unwrap();
    
    let q = xml_file.q;
    let decoded_q = base64::decode(q.as_bytes()).unwrap();
    
    let dp = xml_file.dp;
    let decoded_dp = base64::decode(dp.as_bytes()).unwrap();

    let dq = xml_file.dq;
    let decoded_dq = base64::decode(dq.as_bytes()).unwrap();
    
    let inverse_q = xml_file.inverse_q;
    let decoded_inverse_q = base64::decode(inverse_q.as_bytes()).unwrap();
    
    let d = xml_file.d;
    let decoded_d = base64::decode(d.as_bytes()).unwrap();
    
    let big_e = BigNum::from_slice(&decoded_e).expect("error");
    let big_n = BigNum::from_slice(&decoded_n).expect("error");
    let big_p = BigNum::from_slice(&decoded_p).expect("error");
    let big_q = BigNum::from_slice(&decoded_q).expect("error");
    let big_dp = BigNum::from_slice(&decoded_dp).expect("error");
    let big_dq = BigNum::from_slice(&decoded_dq).expect("error");
    let big_inverse_q = BigNum::from_slice(&decoded_inverse_q).expect("error");
    let big_d = BigNum::from_slice(&decoded_d).expect("error");

    let rsa = Rsa::from_private_components(big_n, big_e, big_d, big_p, big_q, big_dp, big_dq, big_inverse_q).unwrap();

    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    let _b64_encoded_sig = base64::decode(data).unwrap();
    let _enc = rsa.private_decrypt(&_b64_encoded_sig, &mut buf, Padding::PKCS1_OAEP).unwrap();
    let buf = Arc::new(buf);
    let _b64_encoded_sig = base64::encode(buf.clone().as_ref());

   return Ok(String::from_utf8(buf.clone().as_ref().to_vec()).unwrap()); 

}
