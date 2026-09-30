'use strict';

// defaults, json5 file, then cli flags

const fs = require('fs');
const JSON5 = require('json5');
const _ = require('lodash');

const DEFAULTS = {
  title: 'Document',
  render: { gfm: true, breaks: false, sanitize: true },
  output: { wrap: true },
};

function readConfigFile(file) {
  if (!file || !fs.existsSync(file)) return {};
  return JSON5.parse(fs.readFileSync(file, 'utf8'));
}

function loadConfig(file, overrides = {}) {
  // _.merge skips undefined, file title stays
  const merged = _.merge({}, DEFAULTS, readConfigFile(file), overrides);
  return {
    title: _.get(merged, 'title', DEFAULTS.title),
    render: _.get(merged, 'render', DEFAULTS.render),
    wrap: _.get(merged, 'output.wrap', true),
  };
}

module.exports = { DEFAULTS, loadConfig };
