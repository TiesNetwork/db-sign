var EUtils = require('ethereumjs-util');
var CJson = require('canonical-json');

function recoverWallet(phrase){
	//As in https://github.com/paritytech/parity/blob/master/js/src/api/local/ethkey/worker.js
	let hashed = EUtils.sha3(phrase);

	for(var i=0; i<16384; ++i)
	   hashed = EUtils.sha3(hashed);

    while(true){
	   	hashed = EUtils.sha3(hashed);
		if (EUtils.isValidPrivate(hashed)) {
			// No compression, slice out last 64 bytes
        	const publicBuf = EUtils.privateToPublic(hashed);
			const address = EUtils.publicToAddress(publicBuf);

			if (address[0] !== 0) {
 				continue;
        	}

        	const wallet = {
				secret: hashed,
  				public: publicBuf,
  				address: EUtils.bufferToHex(address)
			};

			return wallet;
		}
    }
}

function hashMessage(message){
	return EUtils.hashPersonalMessage(EUtils.toBuffer(CJson(message, (key, value) => {
		if(key == '__signature')
			return;
		return value;
	})));
}

/**
	@param message {
		address: string
		signature: string
		timestamp: long
		payload: object
	}
*/
function signMessage(message, privateKey){
	message.__timestamp = +new Date();

	const mhash = hashMessage(message);
	const sig = EUtils.ecsign(mhash, privateKey);
	const signature = EUtils.toRpcSig(sig.v, sig.r, sig.s);

	const pubKey = EUtils.privateToPublic(privateKey);
	let address = EUtils.bufferToHex(EUtils.publicToAddress(pubKey));

	if(message.__address != address)
		throw new Error('Private key to sign with does not match public key');

	message.__signature = signature;
	return message;
}

/**
	@param message {
		address: string
		signature: string
		timestamp: long
		payload: object
	}
*/
function checkMessage(message){
    let msgHash = hashMessage(message);
    let sigParts = EUtils.fromRpcSig(message.__signature);
    let pubKey = EUtils.ecrecover(msgHash, sigParts.v, sigParts.r, sigParts.s);
    let address = EUtils.bufferToHex(EUtils.publicToAddress(pubKey));

    return address == message.__address;
}

module.exports = {
	recoverWallet: recoverWallet,
	signMessage: signMessage,
	checkMessage: checkMessage
}