'use strict';

// app never touches lodash directly
const _ = require('lodash');

function compile(md) {
  return _.template(md);
}

function render(md, data) {
  return compile(md)(data || {});
}

module.exports = { render };
