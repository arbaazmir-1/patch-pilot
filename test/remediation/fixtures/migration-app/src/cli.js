'use strict';

// prints html, never loads marked
const { readFileSync } = require('node:fs');
const { renderDocument } = require('./render');

const file = process.argv[2];
if (file) process.stdout.write(renderDocument(file, readFileSync(file, 'utf8')));
