'use strict';

// fails unless node satisfies engines
const semver = require('semver');
const pkg = require('../package.json');

const wanted = (pkg.engines && pkg.engines.node) || '*';
if (!semver.satisfies(process.version, wanted)) {
  console.error(`Node ${process.version} does not satisfy engines.node "${wanted}"`);
  process.exit(1);
}
console.log(`Node ${process.version} satisfies engines.node "${wanted}"`);
