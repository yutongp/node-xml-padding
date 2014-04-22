node-xml-padding
================
#####Yutong Pei @ypei

xml encryption padding attack in node.js

####__Simple Usage__

	var xmlattack = require("PROJUCT_PATH/lib/xmlpadatck");
	var oracle = {
		host : '127.0.0.1'
		, port : 8888
		, encryption_path : '/encrypt'
		, verification_path : '/verify'
	};
	
	xmlattack.recoverEncryted2PlainXML("path/to/encryptedXML", oracle, function(err, result){
        console.log(result) //decrypted string as result
    });

####__Project Files__
	
	./
	|-oracle.js: the encrypt(POST to encryption_path) and verify(POST to 
				verification_path) oracle
	|
	|-./config
	|	|-config.js: store all config
	|
	|-encrypt.js: encrypt plaintext xml
	|
	|-./test
	|	|-xmlpadding.attack.js: unit test on attack
	|	|-xmlpadding.oracle.js: unit test on oracle
	|
	|-./lib
		|-xmlpadatck.js: the attack script

####__Test__

0. Install [node.js](http://nodejs.org)
1. Generate test plain xml as test/testN-plaintext.xml
2. Start oracle

		node oracle.js

3. Encrypt xml

		node encrypt.js test/testN-plaintext.xml
		
4. Add test in test/xmlpadding.attack.js

		 it('should pass testN xml', function (done) {
		 	xmlPaddingAttackVerifier('/testN-encrypted.xml', '/testN-plaintext.xml', function(err, result, plain){
          		assert.equal(err, null);
          		assert.equal(result, plain);
    		}, done);
    	});

5. run test

		mocha --timeout 60000000
		
####__Details__

######Attack 
The attack follows described in [__How to Break XML Encryption__](https://www.nds.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2011/10/22/HowToBreakXMLenc.pdf)

The general idea is verify oracle for XML encryption on ascii will return Error on invalid characters. Therefore, by split ascii characters in to TypeA(occurs error) and TypeB(not occurs error), adversary recover plain text from cipher text by alter each byte TypeB character to specific TypeA character, then target which TypeB character it is.

The attack is split into two major parts:

The __FindIV__ takes cipher text C and returns an initialization vector iv such that the cipher text c = (iv, C[i]) is well-formed where i is block index

The __FindXbyte__ takes byte index j and a well-formed c = (iv, C[i]) from __FindIV__ and returns the j-th byte x[j] of the CBC decryption intermediate value x = Dec(k, C[i]). Finally m can be recovered by x easily since m[i] = x[i] XOR iv 

For more information, please read the original paper 

######beyond the paper
In this project I did two things beyond the paper:

1. Fix the problem that a full 0x10 padding block will always occurs TypeA error regardless how padding changes
2. Able to handle self closed tags like: <tag/> which are not described in original paper

######further
Further improvement for this project:

1. optimize the algorithm to accurate break spead 

