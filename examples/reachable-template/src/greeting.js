const _ = require('lodash');

function renderGreeting(template, data) {
  const compiled = _.template(template);
  return compiled(data);
}

module.exports = { renderGreeting };
