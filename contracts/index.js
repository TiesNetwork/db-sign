let contract = require('truffle-contract');

module.exports = function(contract_name, provider){
	let c = contract(require('./' + contract_name + '.json'));
	c.setProvider(provider);
	return c;
}