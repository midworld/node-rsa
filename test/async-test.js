var 
  fs = require('fs'),
  assert = require('assert');

var rsa = require('../rsa');

var plaintext = "The Plaintext";

// Test RSA routines - keypair:
var rsaPublic = fs.readFileSync("rsa.public", 'ascii');
var rsaPrivate = fs.readFileSync("rsa.private", 'ascii');
var passphrase = "foobar";

var params = { publicKey: rsaPublic, privateKey: rsaPrivate, passphrase: passphrase };
var keypair = rsa.createRsaKeypair(params);

var i;
var ciphertext, plaintext_again;

var TEST_COUNT = 100;

var s = new Date();

for (i = 0; i < TEST_COUNT; i++) {
  ciphertext = keypair.encryptSync(plaintext, 'utf8', 'base64');
  plaintext_again = keypair.decryptSync(ciphertext, 'base64', 'utf8');
  
  assert.equal(plaintext, plaintext_again);
}

var t = new Date();

var blockingTime = t - s;

console.log('blocking encrypt/decrypt test(msec):', blockingTime);

var count = 0;

s = new Date();

var p = null;

for (i = 0; i < TEST_COUNT; i++) {
  keypair.encrypt(plaintext, 'utf8', 'base64', function (err, ciphertext) {
    keypair.decrypt(ciphertext, 'base64', 'utf8', function (err, plaintext_again) {
      assert.equal(plaintext, plaintext_again);

      if (++count == TEST_COUNT) {
        t = new Date();

        var nonblockingTime = t - s;
        var ratio = blockingTime / nonblockingTime;

        console.log('non-blocking encrypt/decrypt test(msec):', nonblockingTime,
          ratio.toString().replace(/(\.\d{2}).*$/, "$1") + "x faster");
      }
    });
  });
}
