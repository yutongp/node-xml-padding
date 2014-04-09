var assert = require('assert')
    , fs = require('fs')
    , http = require('http')
    , xmlattack = require("../lib/xmlpadatck")



var xmlPaddingAttackVerifier = function (xmlEncryptedFile, xmlPlainFile, callback) {
    var xmlPlain = fs.readFileSync(__dirname + xmlPlainFile);
    xmlattack.recoverEncryted2PlainXML(__dirname + xmlEncryptedFile, function(err, result){
          assert.equal(result, xmlPlain.toString());
          callback();
    });
}

describe('test on xml padding attack', function() {
  it('should pass test0 xml', function (done) {
    xmlPaddingAttackVerifier('/test0-encrypted.xml', '/test0-plaintext.xml', done);
  });
  it('should pass test1 xml', function (done) {
    xmlPaddingAttackVerifier('/test1-encrypted.xml', '/test1-plaintext.xml', done);
  });
});
