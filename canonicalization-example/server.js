// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const requestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 
  max: 100, 
  message: 'Too many requests, please try again later.'
});

const app = express();
app.use(requestLimiter);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}


// Secure route
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const safePath = resolveSafe(BASE_DIR, filename);
    if (!safePath.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(safePath)) return res.status(404).json({ error: 'File not found' });

    const fileContent = fs.readFileSync(safePath, 'utf8');
    res.json({ path: safePath, content: fileContent });
  }
);

// Vulnerable route (demo)
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  if(filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const resolvedPath = path.resolve(BASE_DIR, filename);
  if (!resolvesPath.startsWith(BASE_DIR)) {
    return res.status(400).json({ error: 'Path detected'});
  }
  
  if (!fs.existsSync(resolvedPath)) 
    return res.status(404).json({ error: 'File not found', path: resolvedPath });

  const fileContent = fs.readFileSync(resolvedPath, 'utf8');
  res.json({ path: resolvedPath, fileContent });
});



// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(name => {
    const d = path.dirname(p);
    const p = path.resolve(BASE_DIR, name);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); 
    fs.writeFileSync(p, samples[name], 'utf8');
    
  });
  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;


