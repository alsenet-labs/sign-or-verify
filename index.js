#!/usr/bin/env node
/*
* Copyright (c) 2018 ALSENET SA
*
* Author(s):
*
*      Luc Deschenaux <luc.deschenaux@freesurf.ch>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/

'use strict';
var Q=require('q');
var request=require('request');
var jsrsasign=require('jsrsasign');
var DEBUG=false;

if (process && process.title=='node') {
  var runningInNode=true;
  var fs=require('fs');
}

if (module && ((runningInNode && module.parent) || (!runningInNode && module.exports))) {
  // running as module
  module.exports={
    signOrVerify: signOrVerify,
    sign: function(options){
      options.action='SIGN';
      return signOrVerify(options);
    },
    verify: function(options){
      options.action='VERIFY';
      return signOrVerify(options);
    }
  }

} else {
  // runing as script
  if (runningInNode) {
    function collect(val, memo) {
      memo.push(val);
      return memo;
    }
    var action;
    var program=require('commander');

    var options;

    program.version('1.0.0')
    .option('-A, --list-algorithms')
    .option('-D, --debug');

    program
    .command('sign')
    .description('Compute a signature')
    .option('-p, --pem <filename|string>', 'private key in pkcs8 format')
    .option('-a, --algorithm <type>')
    .option('-i, --input <file>', 'file to process', collect, [])
    .action(function(_options){
      if (arguments.length>1) {
        throw new Error('Invalid argument');
      }
      options=_options;
      options.action='SIGN';
    });

    program
    .command('verify')
    .description('Verify a signature')
    .option('-p, --pem <filename|string|url>', 'public key in pkcs8 format or https url (to use website x509 certificate)')
    .option('-a, --algorithm <type>')
    .option('-s, --signature <file>','signature to verify', collect, [])
    .option('-i, --input <file>', 'file to process', collect, [])
    .action(function(_options){
      if (arguments.length>1) {
        throw new Error('Invalid argument');
      }

      options=_options;
      options.action='VERIFY';
    });

    program.parse(process.argv);

    if (program.debug) {
      DEBUG=true;
    }

    if (program.listHashTypes) {
      console.log(JSON.stringify(getHashTypeList(),false,4));
      return;
    }

    if (program.listAlgorithms) {
      console.log(JSON.stringify(getAlgList(),false,4));
      return;
    }

    var results=[];
    var exitCode=0;
    assert(options.input && options.input.length,'No input file specified');

    options.input.reduce(function(promise,input){
      return promise
      .then(function(result){
        return signOrVerify({
          action: options.action,
          pem: options.pem,
          algorithm: options.algorithm,
          input: input,
          signature: ((options.signature)?options.signature[options.input.indexOf(input)]:undefined),
          debug: DEBUG
        })
        .then(function(_result){
          if (options.action=='VERIFY' && _result==false) {
            exitCode=1;
          }
          if (options.input.length>1) {
            results.push({file: input, result: _result});
          } else {
            results=_result;
          }
        })
      })
    }, Q.resolve())
    .then(function(){
      console.log(results);
      process.exit(exitCode);
    })
    .catch(function(err){
      console.error(err);
      process.exit(1);
    });

  }
}

function readFileAsString(input, encoding) {
  var q=Q.defer();
  fs.readFile(input, function(err,buf){
    if (err) {
      q.reject(err);
      return;
    }
    q.resolve(buf.toString(encoding||'utf8'))
  });
  return q.promise;
}

function getHashTypeList() {
  var list=[];
  for (var k in jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER) {
    if (
      jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER.hasOwnProperty(k) &&
      jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER[k]=='cryptojs'
    ) list.push(k);
  }
  return list;
}

function getAlgList() {
  var list=[];
  for (var k in jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER) {
    if (
      jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER.hasOwnProperty(k) &&
      jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER[k]=='cryptojs/jsrsa'
    ) list.push(k);
  }
  return list;
}

function assertAlg(alg) {
  assert(
    jsrsasign.KJUR.crypto.Util.DEFAULTPROVIDER[alg]=='cryptojs/jsrsa',
    'Invalid alg type '+alg+'. Not in ['+getAlgList().join(', ')+']'
  );
}

function assert(conditionIsMet, errmsg, Q){
  if (!conditionIsMet) {
    var err=new Error(errmsg);
    if (Q) {
      return Q.reject(err);
    } else {
      if (DEBUG) {
        throw err;
      } else {
        console.error('Error: '+err.message);
        process.exit(1);
      }
    }
  } else {
    if (Q) {
      return Q.resolve();
    }
  }
}

/**
  @method signOrVerify
  @desc generate or verify signature
  @param {Object} options
  @param {string} options.action - SIGN or VERIFY (optional: can be determined by the pem type if it's only a priv or pub key)
  @param {string} options.pem - Can be the PEM in pkcs8 format itself, or a filename, or a https url (in the latter case the public x509 certificate of the website will be used to check the signature)
  @param {Object} options.key - jsrsasign.KEYUTIL key object (options.pem will be ignored)
  @param {string} options.algorithm - Signature algorithm
  @param {string} options.input - File to be signed / verified
  @param {string} options.data - Data to be signed / verified (options.input will be ignored)
  @param {string} options.signature - Signature file to validate (optional)
  @param {string} options.sigString - Signature to validate (options.signature will be ignored)
  @return {Object} promise - returns the signature (SIGN) or a boolean (VERIFY)

*/
function signOrVerify(options) {
  var pem=options.pem;
  var key=options.key;
  var algorithm=options.algorithm;
  var input=options.input;
  var signature=options.signature;
  var sigString=options.sigString;


  assert((pem && pem.length) || (key && key.type),'no key or PEM specified');
  assert(input||options.data,'input file not specified');
  assertAlg(algorithm);

  if (options.action&&options.action=='VERIFY') {
    assert(signature||sigString,'Signature file not specified');
  }

  var promise=Q.resolve();

  if (key && key.type) {
    delete options.pem;
  
  } else {
    delete options.key;

    if (pem.substr(0,10)==='-----BEGIN') {
      // assume pem is a PEM string
      promise=promise.then(function(){
        return pem;
      });

    } else {
      if (fs && fs.existsSync(pem)) {
        // assume pem is a filename and get the private key or certificate from disk
        promise=promise.then(function(){
          return readFileAsString(pem);
        });

      } else if (pem.match(/^https/i)) {
        // assume pem is a https URL and get remote certificate from URL
        var q=Q.defer();
        var req=request({
            uri: pem
        });
        req.on('response', function(res){
          try {
            q.resolve([
              '-----BEGIN CERTIFICATE-----',
              res.req.connection.getPeerCertificate().raw.toString('base64'),
              '-----END CERTIFICATE-----'
            ].join(''));
          } catch(err){
            q.reject(err);
          }
        });
        req.on('error', q.reject);
        promise=promise.then(function(){
          return q.promise;
        });

      } else {
        return Q.reject(new Error('Cannot read PEM: '+pem));
      }
    }
    promise=promise.then(function(pemString){
      options.pemString=pemString;
    });
  }

  return promise
  .then(function(){
    // pass or read the data to be signed or verified
    return (options.data)?options.data:readFileAsString(input);

  })
  .then(function(data){
    options.data=data;
    // read the signature file, if any.
    if (options.signature && !options.sigString) {
      return readFileAsString(options.signature)
      .then(function(sigString){
        options.sigString=sigString;
        return options;
      });

    } else {
      return options;
    }
  })
  // sign or verify
  .then(doSignOrVerfiy);

}

function doSignOrVerfiy(options){
  var keyObj = options.key || jsrsasign.KEYUTIL.getKey(options.pemString);
  var sig = new jsrsasign.KJUR.crypto.Signature({"alg": options.algorithm});
  sig.init(keyObj);
  sig.updateString(options.data);
  switch(options.action||sig.state) {
    case 'SIGN': return sig.sign();
    case 'VERIFY': return sig.verify(options.sigString);
    default: throw new Error((options.action?'Unhandled action: '+options.action:'Unhandled signature state: '+state));
  }
}
