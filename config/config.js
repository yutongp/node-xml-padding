var fs = require('fs');

var oracleConfig = {
  host : '127.0.0.1'
  , port : 8888
  , encryption_path : '/encrypt'
  , verification_path : '/verify'
  , rsa_pub: fs.readFileSync(__dirname + '/../test/test-auth0_rsa.pub')
  , pem: fs.readFileSync(__dirname + '/../test/test-auth0.pem')
  , key: fs.readFileSync(__dirname + '/../test/test-auth0.key')
  , encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
  , keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
  , autopadding: false
};

exports = module.exports = {
  oracle: oracleConfig
};
