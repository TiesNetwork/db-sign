/**
 * Created by Dukei on 14.06.2017.
 */

var assert = require('assert');
var dbs = require('../index.js');

describe('Ties Basic functions', function() {
    describe('cryptography', function() {
        it('should user restore from phrase', async function() {
            let wallet = dbs.recoverWallet('crunchy protozoan magazine punctured unicycle overrate antacid jokester salami platypus fracture mute');
            assert.ok(wallet.address == '0x00dbD017A900258A242599624781f7423969c671'.toLowerCase());
        });

        it('should encrypt and decrypt wallet', async function() {
            let wallet = dbs.generateNewWallet();
            let encrypted = dbs.encryptPrivateKey(wallet.secret, 'password');

            let newwallet = dbs.recoverWalletFromEncryptedPrivateKey(encrypted, 'password');
            assert.equal(wallet.address, newwallet.address, 'Wallet can not be decrypted!');
        });

        it('should encode and decode invite', async function() {
            let wallet = dbs.recoverWallet('crunchy protozoan magazine punctured unicycle overrate antacid jokester salami platypus fracture mute');
            let encodedInvite = dbs.encodeInvitation(1, wallet.secret);
            let invite = dbs.decodeInvitation(encodedInvite);

            assert.equal(invite.address, '0x00dbD017A900258A242599624781f7423969c671'.toLowerCase(), "Invite address is wrong!");
            assert.equal(invite.index, 1, "Invite index is wrong!");
        });
    });
});
