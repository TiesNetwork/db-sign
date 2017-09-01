const EC = require('../index.js');

let _listenedAddresses = {}, func_id = 0;

class BlockChain {
    constructor(provider){
        this.Registry = null;
        this.TieToken = null;
        this.Invitation = null;
        this.RegistryContract = null;
        this.TieTokenContract = null;
        this.InvitationContract = null;
        this.provider = provider;
    }

    async connect() {
        const Contract = EC.getContract;
        this.TieTokenContract = Contract('TieToken', this.provider);
        this.RegistryContract = Contract('Registry', this.provider);
        this.InvitationContract = Contract('Invitation', this.provider);

        this.web3 = this.TieTokenContract.web3;

        const PromisifyWeb3 = require("./promisifyWeb3.js");
        PromisifyWeb3.promisify(this.web3);

        [this.Registry, this.TieToken, this.Invitation] = await Promise.all([this.RegistryContract.deployed(), this.TieTokenContract.deployed(), this.InvitationContract.deployed()]);
    }

    async invitationRedeem(code, to, from){
        let invite = EC.decodeInvitation(code);
        let address = to;

        let ok = await this.Invitation.isInvitationAvailable(invite.address, invite.index);
        if(!ok)
            throw new Error('This invitation is no longer available');

        let tx = await this.Invitation.redeem(address, invite.address, invite.index, invite.sig_v, invite.sig_r, invite.sig_s, {from: from});
        let evt = tx.logs[0];
        if(!evt)
            throw new Error('Unspecified error!');
        if(evt.event == 'Error')
            throw new Error(evt.args.msg);

        return evt.event;
    }

    async listenTransfer(address, cb){
        let self = this;
        await this._listenBalance(address, cb, async address => {
            return await self.TieToken.balanceOf(address);
        });
    }

    async listenBalance(address, cb){
        let self = this;
        await this._listenBalance(address, cb, async address => {
            return await self.web3.eth.getBalancePromise(address);
        });
    }

    async listenDeposit(address, cb){
        let self = this;
        await this._listenBalance(address, cb, async address => {
            return await self.Registry.getDeposit(address);
        });
    }

    async _listenBalance(address, cb, getBalanceFunc){
        const timer = require('timers');
        if(!getBalanceFunc.id)
            getBalanceFunc.id = ++func_id;

        let addrinfo = _listenedAddresses[getBalanceFunc.id];
        if(!addrinfo) {
            addrinfo = _listenedAddresses[getBalanceFunc.id] = {
                listenTimer: null,
                listenedAddresses: {}
            };
        }

        let {listenTimer, listenedAddresses} = addrinfo;

        let info = listenedAddresses[address];
        if(!info){
            let balance = await getBalanceFunc(address);
            info = {
                balance: balance,
                cb: cb
            };
            listenedAddresses[address] = info;
        }else if(cb){
            info.cb = cb
        }else{ //Remove listener
            delete listenedAddresses[address];
        }

        let addresses = Object.keys(listenedAddresses);
        let self = this;

        if(addresses.length == 0){
            if(listenTimer)
                timer.clearInterval(listenTimer);
        }else if(!listenTimer){
            listenTimer = timer.setInterval(async () => {
                let promises = [];
                addresses.forEach(addr => {
                    promises.push(getBalanceFunc(addr));
                });
                let balances = await Promise.all(promises);
                balances.forEach((balance, i) => {
                    let addr = addresses[i];
                    let info = listenedAddresses[addr];
                    if(!info.balance.eq(balance)){
                        info.cb(balance, addr, info.balance);
                        info.balance = balance;
                    }
                });

            }, 3000);
            listenTimer.unref();
        }
    }
}

module.exports = BlockChain;