var assert = require('assert')
    , fs = require('fs')
    , xmlenc = require("xml-encryption")
    , http = require('http')
    , config = require('../config/config')


var port = config.oracle.port;
var verify = config.oracle.verification_path;
var encrypt = config.oracle.encryption_path;
var host = config.oracle.host;

var encryptOptions = {
  rsa_pub: config.oracle.rsa_pub
  , pem: config.oracle.pem
  , key: config.oracle.key
  , encryptionAlgorithm: config.oracle.encryptionAlgorithm
  , keyEncryptionAlgorighm: config.oracle.keyEncryptionAlgorighm
  , autopadding: false
};

var verifyPost = function (xmlInput, resMeg, cb) {
    var data = fs.readFileSync(__dirname + xmlInput);

    var httpOptions = {
      host: host,
      port: port,
      path: verify,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml',
        'Content-Length': data.length
      }
    };

    var req = http.request(httpOptions, function(res) {
      res.setEncoding('ascii');
      var fullBody = '';

      res.on('data', function(chunk) {
        // append the current chunk of data to the fullBody variable
        fullBody += chunk.toString();
      });

      res.on('end', function() {
        assert.equal(fullBody, resMeg);
        cb();
      });
    });
    req.write(data);
    req.end();
}

describe('test on orcale', function() {
  it('should encrypt plaintext xml', function (done) {

    var xmlInput = '/test1-plaintext.xml';
    var data = fs.readFileSync(__dirname + xmlInput);

    var httpOptions = {
      host: host,
      port: port,
      path: encrypt,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml',
        'Content-Length': data.length
      }
    };

    var req = http.request(httpOptions, function(res) {
      res.setEncoding('ascii');
      var fullBody = '';

      res.on('data', function(chunk) {
        // append the current chunk of data to the fullBody variable
        fullBody += chunk.toString();
      });

      res.on('end', function() {
        xmlenc.decrypt(fullBody, { key: fs.readFileSync(__dirname + '/test-auth0.key'), autopadding: true}, function(err, decrypted) {
          assert.equal(decrypted, data.toString());
          done();
        });
      });
    });
    req.write(data);
    req.end();

  });

  it('verify encrypted text0 xml, return ok if xml is fine', function (done) {
    verifyPost('/test0-encrypted.xml', 'Decrypt: OK\r\n', done);
  });

  it('verify encrypted text1 xml, return ok if xml is fine', function (done) {
    verifyPost('/test1-encrypted.xml', 'Decrypt: OK\r\n', done);
  });

  it('verify encrypted text1forge xml, return error if xml has padding err', function (done) {
    verifyPost('/test1-encrypted-forge1.xml', 'Decrypt: ERROR\r\n', done);
  });

  it('verify encrypted text2 xml, return error if xml has format err', function (done) {
    verifyPost('/test2-encrypted.xml', 'Decrypt: ERROR\r\n', done);
  });

});
