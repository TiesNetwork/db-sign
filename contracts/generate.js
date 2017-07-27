var Artifactor = require("truffle-artifactor");

var glob = require( 'glob' ),
  	path = require( 'path' );

var artifactor = new Artifactor('./');

glob.sync( './abis/*.json' ).forEach( function( file ) {
	let name = path.basename(file, '.json');
  	let contract_data = require( path.resolve( file ) );
  	contract_data.contract_name = name;

	artifactor.save(contract_data);
});
