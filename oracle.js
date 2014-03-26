var http = require("http")
    , url = require("url")
    , path = require("path")
    , xmlenc = require("xml-encryption")
    , fs = require('fs')
    , querystring = require("querystring")
    , xmldom = require('xmldom');

var port = process.argv[2] || 8888;

var options = {
  rsa_pub: fs.readFileSync(__dirname + '/test/test-auth0_rsa.pub'),
  pem: fs.readFileSync(__dirname + '/test/test-auth0.pem'),
  key: fs.readFileSync(__dirname + '/test/test-auth0.key'),
  encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
  keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  autopadding: false
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
      switch (uri) {
        case '/verify':
          res.writeHead(200, "OK", {'Content-Type': 'text/html'});
          xmlenc.decrypt(fullBody, options, function (err, decrypted) {
            //TODO
          });

        case '/encrypt':
          res.writeHead(200, "OK", {'Content-Type': 'text/xml'});
          xmlenc.encrypt(fullBody, options, function (err, result) {
            res.write(result);
            res.end();
          });
      }
    });
  }
}).listen(port);



//var doc = new xmldom.DOMParser({
  //errorHandler:function(key,msg){console.log(key, msg)}
//}).parseFromString(
    ////'<xml xmlns="a" xmlns:c="./lite">\n'+
        ////'\t<child>test</child>\n'+
        ////'\t<child</child>\n'+
        ////'\t<child/>\n'+
    ////'</xml>'
    //'dasdas','text/xml');
