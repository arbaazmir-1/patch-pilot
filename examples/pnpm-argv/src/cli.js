const minimist = require('minimist');

const args = minimist(process.argv.slice(2), {
  string: ['name'],
  boolean: ['shout'],
  default: { name: 'world' },
});

let message = `Hello, ${args.name}!`;
if (args.shout) message = message.toUpperCase();
console.log(message);
