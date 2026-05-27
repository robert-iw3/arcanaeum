const express = require('express');
const multer = require('multer');
const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const https = require('https');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const app = express();
const upload = multer({ dest: 'uploads/' });

const requestsTotal = { analyze: 0, login: 0 };
const analysisDuration = [];

app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, maxAge: 3600000 },
}));

app.get('/api/csrf-token', asyncHandler(async (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
}));

app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfToken = req.body.csrfToken || req.headers['x-csrf-token'];
    if (!csrfToken || csrfToken !== req.session.csrfToken) {
      return res.status(403).send('Invalid CSRF token');
    }
  }
  next();
});

app.get('/metrics', asyncHandler(async (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(`
# HELP pcapan_requests_total Total API requests
# TYPE pcapan_requests_total counter
pcapan_requests_total{endpoint="analyze"} ${requestsTotal.analyze}
pcapan_requests_total{endpoint="login"} ${requestsTotal.login}
# HELP pcapan_analysis_duration_seconds Analysis duration
# TYPE pcapan_analysis_duration_seconds histogram
${analysisDuration.map((d, i) => `pcapan_analysis_duration_seconds ${d} ${i+1}`).join('\n')}
  `);
}));

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password, csrfToken } = req.body;
  if (username === 'user' && password === 'pass') {
    const token = jwt.sign({ user: username }, process.env.JWT_SECRET || 'secret', { expiresIn: '1h' });
    requestsTotal.login += 1;
    res.json({ token, csrfToken });
  } else {
    res.status(401).send('Invalid credentials');
  }
}));

const authenticate = asyncHandler(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Unauthorized');
  jwt.verify(token, process.env.JWT_SECRET || 'secret');
  next();
});

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many requests, try again later',
});

app.post('/api/analyze', authenticate, limiter, upload.single('pcapDir'), asyncHandler(async (req, res) => {
  const start = Date.now();
  const dir = path.resolve(req.file.path);
  await new Promise((resolve, reject) => {
    exec(`pcapan --dir ${dir} --whitelist whitelist.yaml --output results.json`, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr));
      resolve();
    });
  });
  const duration = (Date.now() - start) / 1000;
  analysisDuration.push(duration);
  requestsTotal.analyze += 1;
  const results = await fs.readFile('results.json', 'utf8');
  res.json(JSON.parse(results));
}));

const options = {
  cert: fs.readFileSync(path.join(__dirname, 'certs/server.crt')),
  key: fs.readFileSync(path.join(__dirname, 'certs/server.key')),
};

https.createServer(options, app).listen(3000, () => console.log('Server on HTTPS 3000'));