var http = require("http")
    , url = require("url")
    , path = require("path")
    , xmlenc = require("xml-encryption")
    , fs = require('fs')
    , querystring = require("querystring")
    , xmldom = require('xmldom')
    , config = require('./config/config')

var port = config.oracle.port;
var verify = config.oracle.verification_path;
var encrypt = config.oracle.encryption_path;
var host = config.oracle.host;

var encrypt_options = {
  rsa_pub: config.oracle.rsa_pub
  , pem: config.oracle.pem
  , key: config.oracle.key
  , encryptionAlgorithm: config.oracle.encryptionAlgorithm
  , keyEncryptionAlgorighm: config.oracle.keyEncryptionAlgorighm
  , autopadding: false
};

http.createServer(function(req, res) {

  if (req.method === "POST") {
    console.log("[200] " + req.method + " to " + req.url);
    var fullBody = '';

    req.on('data', function(chunk) {
      // append the current chunk of data to the fullBody variable
      fullBody += chunk.toString();
    });

    req.on('end', function() {
      var decodedBody = querystring.parse(fullBody);
      var uri = url.parse(req.url).pathname
        , filename = path.join(process.cwd(), uri);
      console.log(uri);
      switch (uri) {
        case verify:
          res.writeHead(200, "OK", {'Content-Type': 'text/html'});
          xmlenc.decrypt(fullBody, encrypt_options, function (err, decrypted) {
            var verifyACK = function (v) {
              if (v) {
                res.write("Decrypt: OK\r\n");
              } else {
                res.write("Decrypt: ERROR\r\n");
              }
              res.end();
            }
            var valid = true;
            console.log(err, decrypted);
            var rawDecrytped = new Buffer(decrypted, 'ascii');
            var padding = rawDecrytped[rawDecrytped.length - 1];
            console.log(rawDecrytped.toString('hex'), padding);
            if (padding <= 0x10 && padding >= 0x01) {
              var doc = new xmldom.DOMParser({
                errorHandler:function(key,msg){
                  console.log(key, msg);
                  valid = false;
                }
              }).parseFromString(rawDecrytped.toString('ascii', 0, rawDecrytped.length - 1 - padding), 'text/xml');
            } else {
              valid = false;
            }
            verifyACK(valid);
          });

        case encrypt:
          res.writeHead(200, "OK", {'Content-Type': 'text/xml'});
          xmlenc.encrypt(fullBody, encrypt_options, function (err, result) {
            res.write(result);
            res.end();
          });
      }
    });
  }
}).listen(port);
