// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();
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

funcrion isInsideBaseDir(finalPath) {
  return (
    finalPath === Base_DIR ||
    finalPath.startsWith(Base_DIR + path.sep)
  );
}
function validateFilename(name) {
  if (name.includes('\0')) return false;
  if (name.includes('/')) || name.includes('\\')) return false;
  if (name.includes('..')) return false;
  return true:
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
      if (!validateFilename(value)) {
        throw new Error('Invalid filename: illegal characters');
    }
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    if (!isInsideBaseDir(normalized)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// Vulnerable route (demo)
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  if(!validateFilename(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const resolvedPath = resolveSafe(BASE_DIR, filename); // intentionally vulnerable
  
  if (!isInsideBaseDir(resolvedPath)) {
    return res.status(403).json({ error: 'Path detected'});
  }
  
  if (!fs.existsSync(resolvedPath)) 
    return res.status(404).json({ error: 'File not found', path: resolvedPath });

  const content = fs.readFileSync(resolvedPath, 'utf8');
  res.json({ path: resolvedPath, content });
});

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(name => {
    if (!validateFilename(name)) return;
    
    const p = path.resolve(BASE_DIR, name);
  
    if (isInsideBaseDir(p)) {
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


