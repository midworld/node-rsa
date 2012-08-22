// load core crypto to get OpenSSL initialized
var crypto = require('crypto'), rsa;

try {
  var binding = require('../build/Release/node_rsa'),
  RsaKeypair = binding.RsaKeypair;
  rsa = true;
} catch (e) {
  rsa = false;
}

var variants = function(o){
  var r = [];
  for(var n in o){
    r.push(n);
    r.push(', ');
  }
  r.splice(r.length-2, 0, ' or ');
  return r.join('');
},
binEnc = {
  binary: 0,
  base64: 0,
  hex: 0
},
checkBinEnc = function(enc, func){
  if(!(enc in binEnc))
    throw new Error('RsaKeypair.'+func+' encoding can be '+
                    variants(binEnc)+' but '+enc+' given!');
},
RsaKeypairP = RsaKeypair.prototype,
origEncryptSync = RsaKeypairP.encryptSync,
origDecryptSync = RsaKeypairP.decryptSync,
origEncrypt = RsaKeypairP.encrypt,
origDecrypt = RsaKeypairP.decrypt,
origGetBignum = RsaKeypairP.getBignum,
origGetModulus = RsaKeypairP.getModulus,
origGetExponent = RsaKeypairP.getExponent;

RsaKeypairP.encryptSync = function(data, dec, enc){
  if(typeof dec != 'string'){
    dec = 'utf8';
  }
  if(typeof enc != 'string'){
    enc = 'binary';
  }
  checkBinEnc(enc, 'encrypt');
  return new Buffer(origEncryptSync.call(this, data, dec), 'binary').toString(enc);
};
RsaKeypairP.encrypt = function (data, dec, enc, origCb) {
  if (typeof dec != 'string') {
    dec = 'utf8';
  }
  if (typeof enc != 'string') {
    enc = 'binary';
  }
  checkBinEnc(enc, 'encrypt');
  var cb = function (err, data) {
    if (!err)
      data = new Buffer(data, 'binary').toString(enc);
    origCb(err, data);
  };
  try {
    origEncrypt.call(this, data, dec, cb);
  } catch (e) {
    origCb(e, null);
  }
};
RsaKeypairP.decryptSync = function(data, dec, enc){
  if(typeof dec != 'string'){
    dec = 'binary';
  }
  if(typeof enc != 'string'){
    enc = 'utf8';
  }
  checkBinEnc(dec, 'decrypt');
  return origDecryptSync.call(this, new Buffer(data, dec).toString('binary'), 'binary', enc);
};
RsaKeypairP.decrypt = function (data, dec, enc, cb) {
  if (typeof dec != 'string') {
    dec = 'binary';
  }
  if (typeof enc != 'string') {
    enc = 'utf8';
  }
  checkBinEnc(dec, 'decrypt');
  try {
    origDecrypt.call(this, new Buffer(data, dec).toString('binary'), 'binary', enc, cb);
  } catch (e) {
    cb(e, null);
  }
};
RsaKeypairP.getBignum = function(enc){
  checkBinEnc(enc, 'getBignum');
  return new Buffer(origGetBignum.call(this), 'binary').toString(enc);
};
RsaKeypairP.getModulus = function(enc){
  if(typeof enc != 'string'){
    enc = 'binary';
  }
  checkBinEnc(enc, 'getModulus');
  return new Buffer(origGetModulus.call(this), 'binary').toString(enc);
};
RsaKeypairP.getExponent = function(enc){
  if(typeof enc != 'string'){
    enc = 'binary';
  }
  checkBinEnc(enc, 'getExponent');
  return new Buffer(origGetExponent.call(this), 'binary').toString(enc);
};

exports.RsaKeypair = RsaKeypair;
exports.createRsaKeypair = function(keys) {
  var k = new RsaKeypair();

  if (keys.publicKey) {
    k.setPublicKey(keys.publicKey);
  }

  if (keys.privateKey) {
    if (keys.passphrase) {
      k.setPrivateKey(keys.privateKey, keys.passphrase);
    }
    else {
      k.setPrivateKey(keys.privateKey);
    }
  }

  if (keys.padding) {
    k.setPadding(keys.padding);
  }

  return k;
};
