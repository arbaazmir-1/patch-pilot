# Unreleased Changes

## 🐞 Bug fixes

- Fixed HTTP header conflict between Content-Length and Transfer-Encoding in res.send - by [@YuryShkoda](https://github.com/YuryShkoda) in [#4893](https://github.com/expressjs/express/pull/4893)


    Fixed the behavior of `res.send()` to prevent conflicts between `Content-Length` and `Transfer-Encoding` HTTP headers in responses. The `Content-Length` header in `res.send()` is now only added when a `Transfer-Encoding` header is not present, complying with the HTTP specification that states both headers should not coexist in the same response

## 🚀 Improvements

* Allow conditional revalidation for QUERY requests. `req.fresh` previously only validated freshness for GET and HEAD requests, so QUERY responses never returned 304 despite a matching validator. Since QUERY is a safe, idempotent, and cacheable method that supports conditional requests, it is now included in the freshness check - by [@Cherry](https://github.com/Cherry) in [#7366](https://github.com/expressjs/express/pull/7366)

    ```js
    // QUERY /reports with If-None-Match: "12345"
    app.query('/reports', (req, res) => {
      res.set('ETag', '"12345"');
      res.send(results); // now responds 304 Not Modified
    });
    ```

* Improve HTML structure in `res.redirect()` responses when HTML format is accepted by adding `<!DOCTYPE html>`, `<title>`, and `<body>` tags for better browser compatibility - by [@Bernice55231](https://github.com/Bernice55231) in [#5167](https://github.com/expressjs/express/pull/5167)

* When calling `app.render` with options set to null, the locals object is handled correctly, preventing unexpected errors and making the method behave the same as when options is omitted or an empty object is passed - by [AkaHarshit](https://github.com/AkaHarshit) in [#6903](https://github.com/expressjs/express/pull/6903)

    ```js
    app.render('index', null, callback); // now works as expected
    ```

* Upgrade `content-type` to `^2.0.0`, bringing a faster parser (~1.5x quicker `Content-Type` parsing/formatting in `res.send()`) along with a behavior change: `res.send()` now keeps any existing parameters when adding the charset and no longer throws on a `Content-Type` that fails to parse - by [@blakeembrey](https://github.com/blakeembrey) in [#7234](https://github.com/expressjs/express/pull/7234)

    ```js
    res.set('Content-Type', 'text/plain; foo=bar').send('hey');
    // -> Content-Type: text/plain; foo=bar; charset=utf-8
    ```

* The default error handler now logs the full error object instead of only its stack trace, so nested details such as `Error.cause` and library-specific properties (e.g. Sequelize's `parent`/`original`) are no longer swallowed - by [@Nitin-Mohapatra](https://github.com/Nitin-Mohapatra) in [#6464](https://github.com/expressjs/express/pull/6464)

* Upgrade `content-disposition` to `^2.0.0`, which changes the `Content-Disposition` header emitted by `res.download()`, `res.attachment()`, and `res.sendFile()`: file names that are valid HTTP tokens are no longer wrapped in quotes. This is equivalent per RFC 6266, but applications asserting on the exact header bytes should update their expectations - by [@blakeembrey](https://github.com/blakeembrey) in [#7233](https://github.com/expressjs/express/pull/7233)

    ```js
    res.attachment('user.html');
    // before -> Content-Disposition: attachment; filename="user.html"
    // after  -> Content-Disposition: attachment; filename=user.html
    ```

* Upgrade `body-parser` to `^2.3.0`, which fixes [CVE-2026-12590](https://www.cve.org/CVERecord?id=CVE-2026-12590) ([GHSA-v422-hmwv-36x6](https://github.com/expressjs/body-parser/security/advisories/GHSA-v422-hmwv-36x6)): an invalid `limit` option value caused request body size enforcement to be silently disabled (fail-open), allowing a denial of service via arbitrarily large payloads. Invalid `limit` values now throw at parser initialization instead of being ignored

## ⚡ Performance

* Avoid duplicate Content-Type header processing in `res.send()` when sending string responses without an explicit Content-Type header - by [@bjohansebas](https://github.com/bjohansebas) in [#6991](https://github.com/expressjs/express/pull/6991)

5.2.1 / 2025-12-01
=======================

* Revert security fix for [CVE-2024-51999](https://www.cve.org/CVERecord?id=CVE-2024-51999) ([GHSA-pj86-cfqh-vqx6](https://github.com/expressjs/express/security/advisories/GHSA-pj86-cfqh-vqx6))
  * The prior release (5.2.0) included an erroneous breaking change related to the extended query parser. There is no actual security vulnerability associated with this behavior (CVE-2024-51999 has been rejected). The change has been fully reverted in this release.

5.2.0 / 2025-12-01
========================

* Security fix for [CVE-2024-51999](https://www.cve.org/CVERecord?id=CVE-2024-51999) ([GHSA-pj86-cfqh-vqx6](https://github.com/expressjs/express/security/advisories/GHSA-pj86-cfqh-vqx6))
* deps: `body-parser@^2.2.1`
* A deprecation warning was added when using `res.redirect` with undefined arguments, Express now emits a warning to help detect calls that pass undefined as the status or URL and make them easier to fix.

5.1.0 / 2025-03-31
========================

* Add support for `Uint8Array` in `res.send()`
* Add support for ETag option in `res.sendFile()`
* Add support for multiple links with the same rel in `res.links()`
* Add funding field to package.json
* perf: use loop for acceptParams
* refactor: prefix built-in node module imports
* deps: remove `setprototypeof`
* deps: remove `safe-buffer`
* deps: remove `utils-merge`
* deps: remove `methods`
* deps: remove `depd`
* deps: `debug@^4.4.0`
* deps: `body-parser@^2.2.0`
* deps: `router@^2.2.0`
* deps: `content-type@^1.0.5`
* deps: `finalhandler@^2.1.0`
* deps: `qs@^6.14.0`
* deps: `server-static@2.2.0`
* deps: `type-is@2.0.1`

5.0.1 / 2024-10-08
==========

* Update `cookie` semver lock to address [CVE-2024-47764](https://nvd.nist.gov/vuln/detail/CVE-2024-47764)

5.0.0 / 2024-09-10
=========================
* remove:
  - `path-is-absolute` dependency - use `path.isAbsolute` instead
* breaking:
  * `res.status()` accepts only integers, and input must be greater than 99 and less than 1000
    * will throw a `RangeError: Invalid status code: ${code}. Status code must be greater than 99 and less than 1000.` for inputs outside this range
    * will throw a `TypeError: Invalid status code: ${code}. Status code must be an integer.` for non integer inputs
  * deps: send@1.0.0
  * `res.redirect('back')` and `res.location('back')` is no longer a supported magic string, explicitly use `req.get('Referrer') || '/'`.
* change:
  - `res.clearCookie` will ignore user provided `maxAge` and `expires` options
* deps: cookie-signature@^1.2.1
* deps: debug@4.3.6
* deps: merge-descriptors@^2.0.0
* deps: serve-static@^2.1.0
* deps: qs@6.13.0
* deps: accepts@^2.0.0
* deps: mime-types@^3.0.0
  - `application/javascript` => `text/javascript`
* deps: type-is@^2.0.0
* deps: content-disposition@^1.0.0
* deps: finalhandler@^2.0.0
* deps: fresh@^2.0.0
* deps: body-parser@^2.0.1
* deps: send@^1.1.0

5.0.0-beta.3 / 2024-03-25
=========================

This incorporates all changes after 4.19.1 up to 4.19.2.

5.0.0-beta.2 / 2024-03-20
=========================

This incorporates all changes after 4.17.2 up to 4.19.1.

5.0.0-beta.1 / 2022-02-14
=========================

This is the first Express 5.0 beta release, based off 4.17.2 and includes
changes from 5.0.0-alpha.8.

  * change:
    - Default "query parser" setting to `'simple'`
    - Requires Node.js 4+
    - Use `mime-types` for file to content type mapping
  * deps: array-flatten@3.0.0
  * deps: body-parser@2.0.0-beta.1
    - `req.body` is no longer always initialized to `{}`
    - `urlencoded` parser now defaults `extended` to `false`
    - Use `on-finished` to determine when body read
  * deps: router@2.0.0-beta.1
    - Add new `?`, `*`, and `+` parameter modifiers
    - Internalize private `router.process_params` method
    - Matching group expressions are only RegExp syntax
    - Named matching groups no longer available by position in `req.params`
    - Regular expressions can only be used in a matching group
    - Remove `debug` dependency
    - Special `*` path segment behavior removed
    - deps: array-flatten@3.0.0
    - deps: parseurl@~1.3.3
    - deps: path-to-regexp@3.2.0
    - deps: setprototypeof@1.2.0
  * deps: send@1.0.0-beta.1
    - Change `dotfiles` option default to `'ignore'`
    - Remove `hidden` option; use `dotfiles` option instead
    - Use `mime-types` for file to content type mapping
    - deps: debug@3.1.0
  * deps: serve-static@2.0.0-beta.1
    - Change `dotfiles` option default to `'ignore'`
    - Remove `hidden` option; use `dotfiles` option instead
    - Use `mime-types` for file to content type mapping
    - Remove `express.static.mime` export; use `mime-types` package instead
    - deps: send@1.0.0-beta.1

5.0.0-alpha.8 / 2020-03-25
==========================

This is the eighth Express 5.0 alpha release, based off 4.17.1 and includes
changes from 5.0.0-alpha.7.

5.0.0-alpha.7 / 2018-10-26
==========================

This is the seventh Express 5.0 alpha release, based off 4.16.4 and includes
changes from 5.0.0-alpha.6.

The major change with this alpha is the basic support for returned, rejected
Promises in the router.

  * remove:
    - `path-to-regexp` dependency
  * deps: debug@3.1.0
    - Add `DEBUG_HIDE_DATE` environment variable
    - Change timer to per-namespace instead of global
    - Change non-TTY date format
    - Remove `DEBUG_FD` environment variable support
    - Support 256 namespace colors
  * deps: router@2.0.0-alpha.1
    - Add basic support for returned, rejected Promises
    - Fix JSDoc for `Router` constructor
    - deps: debug@3.1.0
    - deps: parseurl@~1.3.2
    - deps: setprototypeof@1.1.0
    - deps: utils-merge@1.0.1

5.0.0-alpha.6 / 2017-09-24
==========================

This is the sixth Express 5.0 alpha release, based off 4.15.5 and includes
changes from 5.0.0-alpha.5.

  * remove:
    - `res.redirect(url, status)` signature - use `res.redirect(status, url)`
    - `res.send(status, body)` signature - use `res.status(status).send(body)`
  * deps: router@~1.3.1
    - deps: debug@2.6.8

5.0.0-alpha.5 / 2017-03-06
==========================

This is the fifth Express 5.0 alpha release, based off 4.15.2 and includes
changes from 5.0.0-alpha.4.

5.0.0-alpha.4 / 2017-03-01
==========================

This is the fourth Express 5.0 alpha release, based off 4.15.0 and includes
changes from 5.0.0-alpha.3.

  * remove:
    - Remove Express 3.x middleware error stubs
  * deps: router@~1.3.0
    - Add `next("router")` to exit from router
    - Fix case where `router.use` skipped requests routes did not
    - Skip routing when `req.url` is not set
    - Use `%o` in path debug to tell types apart
    - deps: debug@2.6.1
    - deps: setprototypeof@1.0.3
    - perf: add fast match path for `*` route

5.0.0-alpha.3 / 2017-01-28
==========================

This is the third Express 5.0 alpha release, based off 4.14.1 and includes
changes from 5.0.0-alpha.2.

  * remove:
    - `res.json(status, obj)` signature - use `res.status(status).json(obj)`
    - `res.jsonp(status, obj)` signature - use `res.status(status).jsonp(obj)`
    - `res.vary()` (no arguments) -- provide a field name as an argument
  * deps: array-flatten@2.1.1
  * deps: path-is-absolute@1.0.1
  * deps: router@~1.1.5
    - deps: array-flatten@2.0.1
    - deps: methods@~1.1.2
    - deps: parseurl@~1.3.1
    - deps: setprototypeof@1.0.2

5.0.0-alpha.2 / 2015-07-06
==========================

This is the second Express 5.0 alpha release, based off 4.13.1 and includes
changes from 5.0.0-alpha.1.

  * remove:
    - `app.param(fn)`
    - `req.param()` -- use `req.params`, `req.body`, or `req.query` instead
  * change:
    - `res.render` callback is always async, even for sync view engines
    - The leading `:` character in `name` for `app.param(name, fn)` is no longer removed
    - Use `router` module for routing
    - Use `path-is-absolute` module for absolute path detection

5.0.0-alpha.1 / 2014-11-06
==========================

This is the first Express 5.0 alpha release, based off 4.10.1.

  * remove:
    - `app.del` - use `app.delete`
    - `req.acceptsCharset` - use `req.acceptsCharsets`
    - `req.acceptsEncoding` - use `req.acceptsEncodings`
    - `req.acceptsLanguage` - use `req.acceptsLanguages`
    - `res.json(obj, status)` signature - use `res.json(status, obj)`
    - `res.jsonp(obj, status)` signature - use `res.jsonp(status, obj)`
    - `res.send(body, status)` signature - use `res.send(status, body)`
    - `res.send(status)` signature - use `res.sendStatus(status)`
    - `res.sendfile` - use `res.sendFile` instead
    - `express.query` middleware
  * change:
    - `req.host` now returns host (`hostname:port`) - use `req.hostname` for only hostname
    - `req.query` is now a getter instead of a plain property
  * add:
    - `app.router` is a reference to the base router

4.20.0 / 2024-09-10
==========
  * deps: serve-static@0.16.0
    * Remove link renderization in html while redirecting
  * deps: send@0.19.0
    * Remove link renderization in html while redirecting
  * deps: body-parser@0.6.0
    * add `depth` option to customize the depth level in the parser
    * IMPORTANT: The default `depth` level for parsing URL-encoded data is now `32` (previously was `Infinity`)
  * Remove link renderization in html while using `res.redirect`
  * deps: path-to-regexp@0.1.10
    - Adds support for named matching groups in the routes using a regex
    - Adds backtracking protection to parameters without regexes defined
  * deps: encodeurl@~2.0.0
    - Removes encoding of `\`, `|`, and `^` to align better with URL spec
  * Deprecate passing `options.maxAge` and `options.expires` to `res.clearCookie`
    - Will be ignored in v5, clearCookie will set a cookie with an expires in the past to instruct clients to delete the cookie

4.19.2 / 2024-03-25
==========

  * Improved fix for open redirect allow list bypass

4.19.1 / 2024-03-20
==========

  * Allow passing non-strings to res.location with new encoding handling checks

4.19.0 / 2024-03-20
==========

  * Prevent open redirect allow list bypass due to encodeurl
  * deps: cookie@0.6.0

4.18.3 / 2024-02-29
==========

  * Fix routing requests without method
  * deps: body-parser@1.20.2
    - Fix strict json error message on Node.js 19+
    - deps: content-type@~1.0.5
    - deps: raw-body@2.5.2
  * deps: cookie@0.6.0
    - Add `partitioned` option

4.18.2 / 2022-10-08
===================

  * Fix regression routing a large stack in a single route
  * deps: body-parser@1.20.1
    - deps: qs@6.11.0
    - perf: remove unnecessary object clone
  * deps: qs@6.11.0

4.18.1 / 2022-04-29
===================

  * Fix hanging on large stack of sync routes

4.18.0 / 2022-04-25
===================

  * Add "root" option to `res.download`
  * Allow `options` without `filename` in `res.download`
  * Deprecate string and non-integer arguments to `res.status`
  * Fix behavior of `null`/`undefined` as `maxAge` in `res.cookie`
  * Fix handling very large stacks of sync middleware
  * Ignore `Object.prototype` values in settings through `app.set`/`app.get`
  * Invoke `default` with same arguments as types in `res.format`
  * Support proper 205 responses using `res.send`
  * Use `http-errors` for `res.format` error
  * deps: body-parser@1.20.0
    - Fix error message for json parse whitespace in `strict`
    - Fix internal error when inflated body exceeds limit
    - Prevent loss of async hooks context
    - Prevent hanging when request already read
    - deps: depd@2.0.0
    - deps: http-errors@2.0.0
    - deps: on-finished@2.4.1
    - deps: qs@6.10.3
    - deps: raw-body@2.5.1
  * deps: cookie@0.5.0
    - Add `priority` option
    - Fix `expires` option to reject invalid dates
  * deps: depd@2.0.0
    - Replace internal `eval` usage with `Function` constructor
    - Use instance methods on `process` to check for listeners
  * deps: finalhandler@1.2.0
    - Remove set content headers that break response
    - deps: on-finished@2.4.1
    - deps: statuses@2.0.1
  * deps: on-finished@2.4.1
    - Prevent loss of async hooks context
  * deps: qs@6.10.3
  * deps: send@0.18.0
    - Fix emitted 416 error missing headers property
    - Limit the headers removed for 304 response
    - deps: depd@2.0.0
    - deps: destroy@1.2.0
    - deps: http-errors@2.0.0
    - deps: on-finished@2.4.1
    - deps: statuses@2.0.1
  * deps: serve-static@1.15.0
    - deps: send@0.18.0
  * deps: statuses@2.0.1
    - Remove code 306
    - Rename `425 Unordered Collection` to standard `425 Too Early`

4.17.3 / 2022-02-16
===================

  * deps: accepts@~1.3.8
    - deps: mime-types@~2.1.34
    - deps: negotiator@0.6.3
  * deps: body-parser@1.19.2
    - deps: bytes@3.1.2
    - deps: qs@6.9.7
    - deps: raw-body@2.4.3
  * deps: cookie@0.4.2
  * deps: qs@6.9.7
    * Fix handling of `__proto__` keys
  * pref: remove unnecessary regexp for trust proxy

4.17.2 / 2021-12-16
===================

  * Fix handling of `undefined` in `res.jsonp`
  * Fix handling of `undefined` when `"json escape"` is enabled
  * Fix incorrect middleware execution with unanchored `RegExp`s
  * Fix `res.jsonp(obj, status)` deprecation message
  * Fix typo in `res.is` JSDoc
  * deps: body-parser@1.19.1
    - deps: bytes@3.1.1
    - deps: http-errors@1.8.1
    - deps: qs@6.9.6
    - deps: raw-body@2.4.2
    - deps: safe-buffer@5.2.1
    - deps: type-is@~1.6.18
  * deps: content-disposition@0.5.4
    - deps: safe-buffer@5.2.1
  * deps: cookie@0.4.1
    - Fix `maxAge` option to reject invalid values
  * deps: proxy-addr@~2.0.7
    - Use `req.socket` over deprecated `req.connection`
    - deps: forwarded@0.2.0
    - deps: ipaddr.js@1.9.1
  * deps: qs@6.9.6
  * deps: safe-buffer@5.2.1
  * deps: send@0.17.2
    - deps: http-errors@1.8.1
    - deps: ms@2.1.3
    - pref: ignore empty http tokens
  * deps: serve-static@1.14.2
    - deps: send@0.17.2
  * deps: setprototypeof@1.2.0

4.17.1 / 2019-05-25
===================

  * Revert "Improve error message for `null`/`undefined` to `res.status`"

4.17.0 / 2019-05-16
===================

  * Add `express.raw` to parse bodies into `Buffer`
  * Add `express.text` to parse bodies into string
  * Improve error message for non-strings to `res.sendFile`
  * Improve error message for `null`/`undefined` to `res.status`
  * Support multiple hosts in `X-Forwarded-Host`
  * deps: accepts@~1.3.7
