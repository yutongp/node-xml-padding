var http = require("http")
    , url = require("url")
    , path = require("path")
    , xmlenc = require("./lib/xml-encryption")
    , fs = require('fs')
    , querystring = require("querystring")
    , xmldom = require('./lib/xmldom')
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



function isInvalidXML(xml, testFunc) {
  var err = false;

  function isInvalidXMLNode(node) {
    var invalid = false;
    if (node.childNodes) {
      for (var i = 0; i < node.childNodes.length; i++) {
        if (node.childNodes[i].data) {
          if (testFunc(new Buffer(node.childNodes[i].data, 'binary'))) {
            invalid = true;
          }
        }
        if (isInvalidXMLNode (node.childNodes[i])) {
          invalid = true;
        }
      }
    }
    return invalid;
  }

  var doc = new xmldom.DOMParser({
    errorHandler:function(key,msg){
      console.log("xxx3xxx", key, msg);
      err = true;
    }
  }).parseFromString(xml, 'text/xml');
  if (err) {
    return true;
  }
  var root = doc.documentElement;
  if (root) {
    return isInvalidXMLNode(root);
  } else {
    return isInvalidXMLNode(doc);
  }
}


function includeTypeAChar(buf) {
  var isTypeAChar = function(c) {
    if (c >= 0x00 && c <= 0x0F) {
      if (c == 0x09 || c == 0x0A || c == 0x0D) {
        return false;
      } else {
        return true;
      }
    } else if (c >= 0x10 && c <= 0x1F) {
      return true;
    } else if (c == 0x26 || c == 0x3C) {
      return true;
    } else {
      return false;
    }
  }

  for (var i = 0; i < buf.length; i++) {
    if (isTypeAChar(buf.readUInt8(i)))
      return true;
  }
  return false;
}

http.createServer(function(req, res) {

  if (req.method === "POST") {
    var fullBody = '';

    req.on('data', function(chunk) {
      // append the current chunk of data to the fullBody variable
      fullBody += chunk.toString();
    });

    req.on('end', function() {
      var decodedBody = querystring.parse(fullBody);
      var uri = url.parse(req.url).pathname
        , filename = path.join(process.cwd(), uri);
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
            var rawDecrytped = new Buffer(decrypted, 'binary');
            var padding = rawDecrytped[rawDecrytped.length - 1];
            console.log("======", rawDecrytped.toString('hex'), padding);
            if (padding <= 0x10 && padding >= 0x01) {
              var source = rawDecrytped.toString('binary', 0, rawDecrytped.length - padding);
              if (source != "") {
                if (isInvalidXML(source, includeTypeAChar)) {
                  valid = false;
                }
              }
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
