/* jshint node: true */
'use strict';

var express = require('express');
var compression = require('compression');
var path = require('path');
var cors = require('cors');
var exists = require('./exists');
var basicAuth = require('basic-auth');
var fs = require('fs');
var ExpressBrute = require('express-brute');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var db = require('./db');

/* Creates and returns a single express server. */
module.exports = function(options) {
    function endpoint(path, router) {
        if (options.verbose) {
            console.log('http://' + options.hostName + ':' + options.port + '/api/v1' + path, true);
        }
        if (path !== 'proxyabledomains') {
            // deprecated endpoint that isn't part of V1
            app.use('/api/v1' + path, router);
        }
        // deprecated endpoint at `/`
        app.use(path, router);
    }

    // eventually this mime type configuration will need to change
    // https://github.com/visionmedia/send/commit/d2cb54658ce65948b0ed6e5fb5de69d022bef941
    var mime = express.static.mime;
    mime.define({
        'application/json' : ['czml', 'json', 'geojson'],
        'text/plain' : ['glsl']
    });

    // initialise app with standard middlewares
    var app = express();
    app.use(compression());
    app.use(cors());
    app.disable('etag');
    if (options.verbose) {
        app.use(require('morgan')('dev'));
    }

    if (typeof options.settings.trustProxy !== 'undefined') {
        app.set('trust proxy', options.settings.trustProxy);
    }

    if (options.verbose) {
        console.log('Listening on these endpoints:', true);
    }
    endpoint('/ping', function(req, res){
      res.status(200).send('OK');
    });

    // We do this after the /ping service above so that ping can be used unauthenticated and without TLS for health checks.

    if (options.settings.redirectToHttps) {
        var httpAllowedHosts = options.settings.httpAllowedHosts || ["localhost"];
        app.use(function(req, res, next) {
            if (httpAllowedHosts.indexOf(req.hostname) >= 0) {
                return next();
            }

            if (req.protocol !== 'https') {
                var url = 'https://' + req.hostname + req.url;
                res.redirect(301, url);
            } else {
                next();
            }
        });
    }

    // using express-session for session cookies
    app.use(session({
        name: 'site_cookie',
        secret: 'my-secret-password',
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 60000
        }
    }));
    app.use(passport.initialize());
    app.use(passport.session());

    // Configure the local strategy for use by Passport.
    //
    // The local strategy require a `verify` function which receives the credentials
    // (`username` and `password`) submitted by the user.  The function must verify
    // that the password is correct and then invoke `cb` with a user object, which
    // will be set at `req.user` in route handlers after authentication.
    passport.use(new LocalStrategy(
      function(username, password, cb) {
        db.users.findByUsername(username, function(err, user) {
          if (err) { return cb(err); }
          if (!user) { return cb(null, false); }
          if (user.password != password) { return cb(null, false); }
          return cb(null, user);
        });
      }));

    // Configure Passport authenticated session persistence.
    //
    // In order to restore authentication state across HTTP requests, Passport needs
    // to serialize users into and deserialize users out of the session.  The
    // typical implementation of this is as simple as supplying the user ID when
    // serializing, and querying the user record by ID from the database when
    // deserializing.
    passport.serializeUser(function(user, cb) {
      cb(null, user.id);
    });

    passport.deserializeUser(function(id, cb) {
      db.users.findById(id, function (err, user) {
        if (err) { return cb(err); }
        cb(null, user);
      });
    });

    var auth = options.settings.basicAuthentication;
    if (auth && auth.username && auth.password) {
        var store = new ExpressBrute.MemoryStore();
        var rateLimitOptions = {
            freeRetries: 2,
            minWait: 200,
            maxWait: 60000,
        };
        if (options.settings.rateLimit && options.settings.rateLimit.freeRetries !== undefined) {
            rateLimitOptions.freeRetries = options.settings.rateLimit.freeRetries;
            rateLimitOptions.minWait = options.settings.rateLimit.minWait;
            rateLimitOptions.maxWait = options.settings.rateLimit.maxWait;
        }
        var bruteforce = new ExpressBrute(store, rateLimitOptions);
        app.use(bruteforce.prevent, function(req, res, next) {
            var user = basicAuth(req);
            if (user && user.name === auth.username && user.pass === auth.password) {
                // Successful authentication, reset rate limiting.
                req.brute.reset(next);
            } else {
                res.statusCode = 401;
                res.setHeader('WWW-Authenticate', 'Basic realm="terriajs-server"');
                res.end('Unauthorized');
            }
        });
    }

    // Serve the bulk of our application as a static web directory.
    var serveWwwRoot = exists(options.wwwroot + '/index.html');
    if (serveWwwRoot) {
        app.use(express.static(options.wwwroot));
    }

    // Proxy for servers that don't support CORS
    var bypassUpstreamProxyHostsMap = (options.settings.bypassUpstreamProxyHosts || []).reduce(function(map, host) {
            if (host !== '') {
                map[host.toLowerCase()] = true;
            }
            return map;
        }, {});

    endpoint('/proxy', require('./controllers/proxy')({
        proxyableDomains: options.settings.allowProxyFor,
        proxyAllDomains: options.settings.proxyAllDomains,
        proxyAuth: options.proxyAuth,
        proxyPostSizeLimit: options.settings.proxyPostSizeLimit,
        upstreamProxy: options.settings.upstreamProxy,
        bypassUpstreamProxyHosts: bypassUpstreamProxyHostsMap,
        basicAuthentication: options.settings.basicAuthentication,
        blacklistedAddresses: options.settings.blacklistedAddresses
    }));

    var esriTokenAuth = require('./controllers/esri-token-auth')(options.settings.esriTokenAuth);
    if (esriTokenAuth) {
        endpoint('/esri-token-auth', esriTokenAuth);
    }

    endpoint('/proj4def', require('./controllers/proj4lookup'));            // Proj4def lookup service, to avoid downloading all definitions into the client.
    endpoint('/convert', require('./controllers/convert')(options).router); // OGR2OGR wrapper to allow supporting file types like Shapefile.
    endpoint('/proxyabledomains', require('./controllers/proxydomains')({   // Returns JSON list of domains we're willing to proxy for
        proxyableDomains: options.settings.allowProxyFor,
        proxyAllDomains: !!options.settings.proxyAllDomains,
    }));
    endpoint('/serverconfig', require('./controllers/serverconfig')(options));

    var errorPage = require('./errorpage');
    var show404 = serveWwwRoot && exists(options.wwwroot + '/404.html');
    var error404 = errorPage.error404(show404, options.wwwroot, serveWwwRoot);
    var show500 = serveWwwRoot && exists(options.wwwroot + '/500.html');
    var error500 = errorPage.error500(show500, options.wwwroot);
    var initPaths = options.settings.initPaths || [];

    if (serveWwwRoot) {
        initPaths.push(path.join(options.wwwroot, 'init'));
    }

    app.use('/init', require('./controllers/initfile')(initPaths, error404, options.configDir));

    var feedbackService = require('./controllers/feedback')(options.settings.feedback);
    if (feedbackService) {
        endpoint('/feedback', feedbackService);
    }
    var shareService = require('./controllers/share')(options.settings.shareUrlPrefixes, options.settings.newShareUrlPrefix, options.hostName, options.port);
    if (shareService) {
        endpoint('/share', shareService);
    }

    app.use(error404);
    app.use(error500);
    var server = app;
    var osh = options.settings.https;
    if (osh && osh.key && osh.cert) {
        console.log('Launching in HTTPS mode.');
        var https = require('https');
        server = https.createServer({
            key: fs.readFileSync(osh.key),
            cert: fs.readFileSync(osh.cert)
        }, app);
    }

    app.get('/', (req, res) => {
        if (req.isAuthenticated()) {
            return res.sendFile('index.html', { root : options.wwwroot});
        }
        else {
            res.redirect('/login');
        }
    });

    app.get('/login', (req, res) => res.sendFile('login.html', { root : options.wwwroot}));
    app.get('/error', (req, res) => res.sendFile('error.html', { root : options.wwwroot}));

    app.post('/',
      passport.authenticate('local', { failureRedirect: '/error' }),
      function(req, res) {
        res.redirect('/');
    });

    return server;
};
