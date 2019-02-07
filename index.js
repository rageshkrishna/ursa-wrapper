'use strict';

var ursa = require('ursa');

module.exports = CryptoWrapper;

//
// Based largely on https://stackoverflow.com/questions/21951304/encrypting-and-decrypting-string-using-ursa-with-nodes-throws-decoding-error/21963273
// Answered by https://stackoverflow.com/users/2267995/marcel-batista
// Licensed under CC-BY-SA-3.0
//
function CryptoWrapper(privateKey, password) {
  if (!privateKey) throw new Error('privateKey is required');
  if (!password) password = '';

  var keyPair = ursa.createPrivateKey(privateKey, password);
  var keySizeBytes = keyPair.getModulus().length;

  this.encrypt = function(clearText) {
    var buffer = new Buffer(clearText);
    var maxBufferSize = keySizeBytes - 42; // Magic number from ursa docs
    var bytesEncrypted = 0;
    var encryptedBuffersList = [];

    // We need to encrypt the incoming clear text in pieces because that's
    // how public key crypto works. The maximum size of the data that can be
    // encrypted is (keySize - 42) bytes. So we loop through the buffer until
    // we've encrypted all the data
    while(bytesEncrypted < buffer.length){
        var amountToCopy = Math.min(maxBufferSize,
            buffer.length - bytesEncrypted);

        var tempBuffer = new Buffer(amountToCopy);

        buffer.copy(tempBuffer, 0, bytesEncrypted,
            bytesEncrypted + amountToCopy);

        var encryptedBuffer = keyPair.encrypt(tempBuffer);
        encryptedBuffersList.push(encryptedBuffer);

        bytesEncrypted += amountToCopy;
    }

    // concatenates all encrypted buffers and returns the corresponding String
    return Buffer.concat(encryptedBuffersList).toString('base64');
  };

  this.decrypt = function(encryptedText) {
    var encryptedBuffer = new Buffer(encryptedText, 'base64');
    var decryptedBuffers = [];

    // if the clear text was encrypted with a key of size N, the encrypted
    // result is a string formed by the concatenation of strings of N bytes
    // long, so we can find out how many substrings there are by diving the
    // final result size by N
    var totalBuffers = encryptedBuffer.length / keySizeBytes;

    // decrypts each buffer and stores result buffer in an array
    for(var i = 0 ; i < totalBuffers; i++){
        // copies next buffer chunk to be decrypted in a temp buffer
        var tempBuffer = new Buffer(keySizeBytes);
        encryptedBuffer.copy(tempBuffer, 0, i*keySizeBytes, (i+1)*keySizeBytes);
        // decrypts and stores current chunk
        var decryptedBuffer = keyPair.decrypt(tempBuffer);
        decryptedBuffers.push(decryptedBuffer);
    }

    // concatenates all decrypted buffers and returns the corresponding String
    return Buffer.concat(decryptedBuffers).toString();
  };

}
