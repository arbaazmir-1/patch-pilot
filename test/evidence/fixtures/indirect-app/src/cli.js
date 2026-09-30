#!/usr/bin/env node
'use strict';

const { render } = require('./templates');
const tools = require('./dynamic');

function main(argv) {
  const [template, fn, value] = argv;
  process.stdout.write(`${render(template, { user: 'you' })}\n`);
  process.stdout.write(`${JSON.stringify(tools.run(fn, value))}\n`);
}

main(process.argv.slice(2));
