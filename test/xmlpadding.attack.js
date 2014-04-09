var assert = require('assert')
    , fs = require('fs')
    , http = require('http')
    , xmlattack = require("../lib/xmlpadatck")




describe('test on xml padding attack', function() {
  var xmlPaddingAttackVerifier = function (xmlEncryptedFile, xmlPlainFile, testFunc, cb) {
    var xmlPlain = fs.readFileSync(__dirname + xmlPlainFile);
    xmlattack.recoverEncryted2PlainXML(__dirname + xmlEncryptedFile, function(err, result){
        testFunc(err, result, xmlPlain.toString());
        cb();
    });
  }

  it('should pass test0 xml', function (done) {
    xmlPaddingAttackVerifier('/test0-encrypted.xml', '/test0-plaintext.xml', function(err, result, plain){
          assert.equal(err, null);
          assert.equal(result, plain);
    }, done);
  });

  it('should pass test1 xml', function (done) {
    xmlPaddingAttackVerifier('/test1-encrypted.xml', '/test1-plaintext.xml', function(err, result, plain){
          assert.equal(err, null);
          assert.equal(result, plain);
    }, done);
  });

  it('should pass test3 xml', function (done) {
    xmlPaddingAttackVerifier('/test3-encrypted.xml', '/test3-plaintext.xml', function(err, result, plain){
          assert.equal(err, null);
          assert.equal(result, plain);
    }, done);
  });

  it('should get err test2 xml', function (done) {
    xmlPaddingAttackVerifier('/test2-encrypted.xml', '/test2-plaintext.xml', function(err, result, plain){
          assert.notEqual(err, null);
    }, done);
  });
});
