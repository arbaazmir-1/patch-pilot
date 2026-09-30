'use strict';

// caller picks the lodash function
const _ = require('lodash');

function run(name, value) {
  return _[name](value);
}

module.exports = { run };
