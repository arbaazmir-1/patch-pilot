#!/usr/bin/env node
'use strict';

// flags via minimist, markdown to html

const fs = require('fs');
const path = require('path');
const parseArgs = require('minimist');
const { loadConfig } = require('./config');
const { renderDocument } = require('./render');

const USAGE = `Usage: vulnerable-app --input <file.md> [--config <file.json5>] [--output <file.html>] [--title <text>]
       cat notes.md | vulnerable-app --input -`;

function readInput(input) {
  if (input === '-') return fs.readFileSync(0, 'utf8');
  return fs.readFileSync(path.resolve(input), 'utf8');
}

function main(argv) {
  const args = parseArgs(argv, {
    string: ['input', 'config', 'output', 'title'],
    boolean: ['help'],
    alias: { i: 'input', c: 'config', o: 'output', t: 'title', h: 'help' },
  });

  if (args.help || !args.input) {
    console.log(USAGE);
    return args.help ? 0 : 1;
  }

  const configFile = args.config || path.join(__dirname, '..', 'app.config.json5');
  const config = loadConfig(configFile, { title: args.title });
  const html = renderDocument(config.title, readInput(args.input), config.render);

  if (args.output) {
    fs.writeFileSync(args.output, html);
    console.log(`Wrote ${args.output}`);
  } else {
    process.stdout.write(html);
  }
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main };
