const EUtils = require('ethereumjs-util');
const CJson = require('canonical-json');

const Base58 = require("base-58");
const CRC32 = require('crc-32');

/**
	@returns wallet {
		secret: Buffer, //Private key
		public: Buffer, //Public key
		address: string, //Ethereum/TiesDB user address
		phrase: string //Recovery phrase
	}
*/
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
  				address: EUtils.bufferToHex(address),
  				phrase: phrase,
			};

			return wallet;
		}
    }
}

function recoverWalletFromPrivateKey(privateKey){
    // No compression, slice out last 64 bytes
    const publicBuf = EUtils.privateToPublic(privateKey);
    const address = EUtils.publicToAddress(publicBuf);

    const wallet = {
        secret: EUtils.toBuffer(privateKey),
        public: publicBuf,
        address: EUtils.bufferToHex(address)
    };

    return wallet;
}

function toJson(obj, omitSignature){
    return CJson(obj, (key, value) => {
        if(omitSignature && key == '__signature')
            return;
        if(value instanceof Buffer)
            return '0x' + value.toString('hex');
        if(value && value.type == 'Buffer' && value.data)
        	return '0x' + Buffer.from(value).toString('hex');
        return value;
    });
}

function hashMessage(message){
    let json = toJson(message, true);
	return EUtils.hashPersonalMessage(EUtils.toBuffer(json));
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

function generateNewWallet(){
	const { randomPhrase } = require('@parity/wordlist');
	let phrase = randomPhrase(12);
	let wallet = recoverWallet(phrase);
	return wallet;
}

function recoverWalletFromEncryptedPrivateKey(encrypted_json_str, password){
    // import node-cryptojs-aes modules to encrypt or decrypt data
    let node_cryptojs = require('node-cryptojs-aes');
    // node-cryptojs-aes main object;
    let CryptoJS = node_cryptojs.CryptoJS;
    // custom json serialization format
    let JsonFormatter = node_cryptojs.JsonFormatter;

    // decrypt data with encrypted json string, passphrase string and custom JsonFormatter
    let buf;
    try {
        let decrypted = CryptoJS.AES.decrypt(encrypted_json_str, password, { format: JsonFormatter });
        let decryptedBase64 = CryptoJS.enc.Utf8.stringify(decrypted);
        buf = Buffer.from(decryptedBase64, 'base64');
    }catch(e) {
        console.error("Error decoding saved wallet:", e);
    }
    if (!buf || buf.length != 32)
        throw new Error('Invalid password!');
    return recoverWalletFromPrivateKey(buf);
}

function encryptPrivateKey(privateKey, password){
    // import node-cryptojs-aes modules to encrypt or decrypt data
    let node_cryptojs = require('node-cryptojs-aes');
    // node-cryptojs-aes main object;
    let CryptoJS = node_cryptojs.CryptoJS;
    // custom json serialization format
    let JsonFormatter = node_cryptojs.JsonFormatter;

    // encrypt data with passphrase string and custom JsonFormatter
    let encrypted = CryptoJS.AES.encrypt(privateKey.toString('base64'), password, { format: JsonFormatter });
    // convert CipherParams object to json string for transmission
    let encrypted_json_str = encrypted.toString();
    return encrypted_json_str;
}

function assertIndexIsNumber(index){
    if(typeof(index) !== 'number')
        throw new Error('index should be number, and it is ' + typeof index);
}

function getInvitationHash(index){
    assertIndexIsNumber(index);
    const prefix = "TIE invitation";
    let indexbuf = EUtils.setLength(EUtils.toBuffer(new EUtils.BN(index)), 32);
    let sha3hash = EUtils.sha3(Buffer.concat([EUtils.toBuffer(prefix), indexbuf]));
    return sha3hash;
}

function encodeInvitation(index, privateKey){
    assertIndexIsNumber(index);
    let sha3hash = getInvitationHash(index);
    let sig = EUtils.ecsign(sha3hash, privateKey);

    return encodeInvitationInner(index, sig.v, sig.r, sig.s);
}

function encodeInvitationInner(index, sig_v, sig_r, sig_s){
    assertIndexIsNumber(index);
    let buf = new Buffer(3 + 1 + 32 + 32 + 4);
    buf.writeUInt32LE(index, 0);

    buf[3] = sig_v;
    sig_r.copy(buf, 4);
    sig_s.copy(buf, 4+32);

    let crc = CRC32.buf(buf.slice(0, buf.length-4));
    buf.writeInt32LE(crc, buf.length-4);

    return Base58.encode(buf);
}

function decodeInvitation(str){
    let code;
    try{
        code = Base58.decode(str);
    }catch(e){
        console.error('Error decoding invitation: ', e);
        throw new Error('Bad invitation code!');
    }
    let buf = new Buffer(code);
    if(buf.length != 3 + 1 + 32 + 32 + 4)
        throw new Error('Invalid invitation code!');
    let crc = CRC32.buf(buf.slice(0, buf.length-4));
    let shouldbecrc = buf.readInt32LE(buf.length-4);
    if(crc != shouldbecrc)
        throw new Error('Bad invitation code!');

    let bufInvite = buf.slice(0, 4);
    let index = bufInvite.readUInt32LE(0, true)&0xFFFFFF;
    let sig_v = buf.readUInt8(3);
    let sig_r = buf.slice(4, 4+32);
    let sig_s = buf.slice(4+32, 4+32+32);

    let sha3hash = getInvitationHash(index);
    let pubKey = EUtils.ecrecover(sha3hash, sig_v, sig_r, sig_s);
    let address = EUtils.publicToAddress(pubKey);

    return {
        index: index,
        address: EUtils.bufferToHex(address),
        sig_v: sig_v,
        sig_r: EUtils.bufferToHex(sig_r),
        sig_s: EUtils.bufferToHex(sig_s)
    };
}

module.exports = {
    recoverWallet: recoverWallet,
	signMessage: signMessage,
	checkMessage: checkMessage,
    recoverWalletFromEncryptedPrivateKey: recoverWalletFromEncryptedPrivateKey,
    recoverWalletFromPrivateKey: recoverWalletFromPrivateKey,
    encryptPrivateKey: encryptPrivateKey,
    generateNewWallet: generateNewWallet,
    encodeInvitation: encodeInvitation,
    decodeInvitation: decodeInvitation,
    messageToJson: toJson,
    EU: EUtils,

    get BlockChain() {
        return require('./classes/BlockChain')
    },
    getContract: require('./contracts'),
};