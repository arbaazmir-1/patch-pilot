const http = require('node:http');
const { renderGreeting } = require('./greeting');

const port = Number(process.env.PORT) || 3000;

http
  .createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const template = url.searchParams.get('template') || 'Hello, <%= name %>!';
    const name = url.searchParams.get('name') || 'world';
    try {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(renderGreeting(template, { name }));
    } catch (error) {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`Bad template: ${error.message}`);
    }
  })
  .listen(port, () => {
    console.log(`Greeting server on http://localhost:${port}/?template=Hi%20<%25=%20name%20%25>&name=Ada`);
  });
