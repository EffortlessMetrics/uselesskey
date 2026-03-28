use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::random();
let rsa = fx.rsa("my-service", RsaSpec::rs256());

let private_pem = rsa.private_key_pkcs8_pem();
let public_der = rsa.public_key_spki_der();
