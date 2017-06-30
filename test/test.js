/**
 * Created by Dukei on 14.06.2017.
 */

var assert = require('assert');
var dbs = require('../index.js');

describe('Ties Client Basic functions', function() {
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
/*
        it('should create user', async function() {
            await Client.saveObject('ties_user', {
                __address: Client.currentUserWallet.address,
                name: 'Test Dmitry Kochin',
                description: "The CTO of Ties.Network",
                keywords: ['blockchain', 'network', 'smart contract', 'cryptocurrency', 'token', 'programming']
            });
            let users = await Client.models.instance.User.findAsync({__address: Client.currentUserWallet.address}, {raw: true});
            let user = users[0];
            assert.ok(user && user.name == 'Test Dmitry Kochin');
        });
*/
    });
});
