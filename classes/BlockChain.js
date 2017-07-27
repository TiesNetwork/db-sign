const EC = require('../index.js');

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
}

module.exports = BlockChain;