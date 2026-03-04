# Fix Patronen Referentie

Code-voorbeelden voor het fixen van veelvoorkomende security kwetsbaarheden. Lees dit bestand alleen wanneer je Stap 5 (manual code fixes) uitvoert.

---

## SQL Injection
Zoek: string concatenatie in queries
Fix: vervang door parameterized queries
```python
# Voor:  cursor.execute("SELECT * FROM users WHERE id=" + user_id)
# Na:    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
```

## XSS Prevention
Zoek: ongeescapte output in templates
Fix: gebruik template engine's auto-escaping of expliciete encoding

## Command Injection
Zoek: shell=True of string-gebaseerde command constructie
Fix: gebruik array-gebaseerde commands zonder shell

## Hardcoded Secrets
Zoek: credentials in broncode
Fix: verplaats naar environment variabelen, informeer gebruiker over rotatie

## Insecure Deserialization
Zoek: unsafe load/parse van untrusted data
Fix: gebruik safe alternatieven (safe_load, JSON, etc.)

## React Unsafe HTML Rendering
Zoek: ongesanitiseerde user input in HTML rendering
Fix: sanitize met DOMPurify library voor het renderen
```jsx
// Voor:  ongesanitiseerde content direct in HTML
// Na:    import DOMPurify from 'dompurify';
//        const clean = DOMPurify.sanitize(userContent);
```

## Supabase service_role misuse
Zoek: `createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)` in client-side code
Fix: verplaats naar server-side (API route, Server Component, of server action)
```typescript
// Voor (client-side):  const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)
// Na (API route):      import { createClient } from '@supabase/supabase-js'
//                      const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)
// Client-side alleen:  const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

## NEXT_PUBLIC_ secrets
Zoek: secrets met `NEXT_PUBLIC_` prefix in env vars
Fix: verwijder `NEXT_PUBLIC_` prefix en verplaats gebruik naar server-only code
```
# Voor (.env):   NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...
# Na (.env):     SUPABASE_SERVICE_ROLE_KEY=eyJ...
# Gebruik alleen in API routes, getServerSideProps, of Server Components
```

## Supabase RLS ontbreekt
Zoek: `.from('table').insert()` / `.update()` / `.delete()` zonder RLS
Fix: wijs de gebruiker op het configureren van RLS in het Supabase dashboard
```sql
-- In Supabase SQL Editor:
ALTER TABLE public.table_name ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can only access own data" ON public.table_name
  FOR ALL USING (auth.uid() = user_id);
```

## Path Traversal
Zoek: user input direct gebruikt in bestandspaden zonder validatie
Fix: normaliseer het pad en controleer of het binnen de toegestane directory valt

```python
# Voor:
import os
def read_file(filename):
    with open("/data/uploads/" + filename) as f:
        return f.read()

# Na:
import os
def read_file(filename):
    base_dir = os.path.realpath("/data/uploads")
    file_path = os.path.realpath(os.path.join(base_dir, filename))
    if not file_path.startswith(base_dir + os.sep):
        raise ValueError("Pad buiten toegestane directory")
    with open(file_path) as f:
        return f.read()
```

```javascript
// Voor (Node.js):
app.get('/file', (req, res) => {
  res.sendFile('/uploads/' + req.query.name);
});

// Na (Node.js):
const path = require('path');
app.get('/file', (req, res) => {
  const baseDir = path.resolve('/uploads');
  const filePath = path.resolve(baseDir, req.query.name);
  if (!filePath.startsWith(baseDir + path.sep)) {
    return res.status(400).send('Ongeldig pad');
  }
  res.sendFile(filePath);
});
```

## Open Redirect
Zoek: redirect naar user-supplied URL zonder validatie
Fix: valideer de redirect URL tegen een allowlist van toegestane hostnames

```python
# Voor:
from flask import redirect, request
@app.route('/redirect')
def do_redirect():
    return redirect(request.args.get('url'))

# Na:
from flask import redirect, request, abort
from urllib.parse import urlparse

ALLOWED_HOSTS = {'www.example.com', 'app.example.com'}

@app.route('/redirect')
def do_redirect():
    url = request.args.get('url', '')
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(400, 'Redirect naar niet-toegestaan domein')
    return redirect(url)
```

## XXE (XML External Entity)
Zoek: XML parsing zonder uitschakelen van externe entiteiten (Java)
Fix: schakel DTD verwerking uit in DocumentBuilderFactory

```java
// Voor:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);

// Na:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

## Weak Crypto (zwakke hashing)
Zoek: gebruik van MD5, SHA1 of DES voor cryptografische doeleinden
Fix: vervang door SHA-256 of sterker

```python
# Voor:
import hashlib
digest = hashlib.md5(data.encode()).hexdigest()

# Na:
import hashlib
digest = hashlib.sha256(data.encode()).hexdigest()
```

```javascript
// Voor (Node.js):
const hash = crypto.createHash('md5').update(data).digest('hex');

// Na (Node.js):
const hash = crypto.createHash('sha256').update(data).digest('hex');
```

```java
// Voor:
MessageDigest md = MessageDigest.getInstance("MD5");

// Na:
MessageDigest md = MessageDigest.getInstance("SHA-256");
```

## Insecure Random
Zoek: gebruik van niet-cryptografische random voor beveiligingsgevoelige doeleinden
Fix: gebruik cryptografisch veilige random generators

```python
# Voor:
import random
token = ''.join(random.choices('abcdef0123456789', k=32))

# Na:
import secrets
token = secrets.token_hex(16)
```

```javascript
// Voor (Node.js):
const token = Math.random().toString(36).substring(2);

// Na (Node.js):
const crypto = require('crypto');
const token = crypto.randomBytes(16).toString('hex');
```

```java
// Voor:
Random random = new Random();
int code = random.nextInt(999999);

// Na:
SecureRandom random = new SecureRandom();
int code = random.nextInt(999999);
```

## Unsafe YAML
Zoek: `yaml.load()` zonder SafeLoader (staat arbitrary code execution toe)
Fix: gebruik `yaml.safe_load()` of expliciet `Loader=yaml.SafeLoader`

```python
# Voor:
import yaml
data = yaml.load(raw_input)

# Na:
import yaml
data = yaml.safe_load(raw_input)
```

## Target _blank zonder rel
Zoek: `target="_blank"` links zonder `rel="noopener noreferrer"`
Fix: voeg `rel="noopener noreferrer"` toe aan alle `target="_blank"` links

```html
<!-- Voor: -->
<a href="https://example.com" target="_blank">Link</a>

<!-- Na: -->
<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>
```

## Insecure Cookies
Zoek: cookies zonder beveiligingsvlaggen
Fix: voeg `secure`, `httpOnly` en `sameSite` flags toe

```javascript
// Voor (Express):
res.cookie('session', token);

// Na (Express):
res.cookie('session', token, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict',
  maxAge: 3600000
});
```

```python
# Voor (Flask):
response.set_cookie('session', token)

# Na (Flask):
response.set_cookie('session', token, secure=True, httponly=True, samesite='Strict')
```

## SSRF (Server-Side Request Forgery)
Zoek: HTTP requests naar user-supplied URLs zonder validatie van private IP ranges
Fix: valideer URL en blokkeer private IP-adressen

```python
# Voor:
import requests
def fetch(url):
    return requests.get(url).text

# Na:
import requests
import ipaddress
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
]

def fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Alleen HTTP(S) toegestaan")
    import socket
    ip = socket.getaddrinfo(parsed.hostname, None)[0][4][0]
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in BLOCKED_RANGES):
        raise ValueError("Toegang tot intern netwerk niet toegestaan")
    return requests.get(url).text
```

## Insecure TLS (Go)
Zoek: TLS configuratie zonder minimum versie of met `InsecureSkipVerify: true`
Fix: stel minimale TLS versie in op 1.2

```go
// Voor:
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,
}

// Na:
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}
```

## NoSQL Injection
Zoek: user input direct in MongoDB queries zonder sanitization
Fix: gebruik parameterized queries met expliciete operators

```javascript
// Voor (MongoDB/Mongoose):
app.get('/user', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  res.json(user);
});

// Na (MongoDB/Mongoose):
app.get('/user', async (req, res) => {
  const username = String(req.body.username);
  const user = await User.findOne({ username: { $eq: username } });
  res.json(user);
});
```

## Prototype Pollution
Zoek: direct mergen van user input in objecten via spread, Object.assign, of lodash.merge
Fix: gebruik Object.create(null) of valideer keys met hasOwnProperty

```javascript
// Voor:
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
const config = merge({}, req.body);

// Na:
function safeMerge(target, source) {
  const safe = Object.create(null);
  const blockedKeys = ['__proto__', 'constructor', 'prototype'];
  for (const key of Object.keys(source)) {
    if (blockedKeys.includes(key)) continue;
    safe[key] = source[key];
  }
  return Object.assign(target, safe);
}
const config = safeMerge({}, req.body);
```

## Security Headers
Zoek: webapplicaties zonder essientiele security headers
Fix: voeg security headers middleware toe

```javascript
// Voor (Express):
const app = express();
app.get('/', (req, res) => res.send('OK'));

// Na (Express met Helmet):
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.get('/', (req, res) => res.send('OK'));
```

```python
# Voor (Flask):
app = Flask(__name__)

# Na (Flask met Talisman):
from flask_talisman import Talisman
app = Flask(__name__)
Talisman(app, content_security_policy={'default-src': "'self'"})
```

```python
# Voor (Django settings.py):
MIDDLEWARE = ['django.middleware.common.CommonMiddleware']

# Na (Django settings.py):
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
]
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
```

## JWT Fixes
Zoek: JWT tokens zonder algorithm verificatie, zonder expiratie, of met "none" algorithm
Fix: verifieer algorithm expliciet en voeg expiratie toe

```javascript
// Voor (Node.js):
const payload = jwt.verify(token, secret);
const token = jwt.sign({ userId: id }, secret);

// Na (Node.js):
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
const token = jwt.sign({ userId: id }, secret, {
  algorithm: 'HS256',
  expiresIn: '1h'
});
```

```python
# Voor:
payload = jwt.decode(token, secret)

# Na:
payload = jwt.decode(token, secret, algorithms=['HS256'])
```

## Mass Assignment
Zoek: alle velden van user input direct toewijzen aan database modellen
Fix: gebruik expliciete field allowlists

```javascript
// Voor (Sequelize):
const user = await User.create(req.body);

// Na (Sequelize):
const user = await User.create({
  name: req.body.name,
  email: req.body.email
});
// Of gebruik attributes bij query:
const user = await User.create(req.body, {
  fields: ['name', 'email']
});
```

```python
# Voor (Django REST Framework):
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# Na (Django REST Framework):
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email']
        read_only_fields = ['id', 'is_admin']
```

## SSTI (Server-Side Template Injection)
Zoek: `render_template_string()` met user input in de template string
Fix: gebruik `render_template()` met aparte template bestanden

```python
# Voor:
from flask import render_template_string, request
@app.route('/greet')
def greet():
    template = f"<h1>Hallo {request.args.get('name')}</h1>"
    return render_template_string(template)

# Na:
from flask import render_template, request
@app.route('/greet')
def greet():
    return render_template('greet.html', name=request.args.get('name'))
# greet.html: <h1>Hallo {{ name }}</h1>
```

## File Upload Validatie
Zoek: file upload zonder MIME type check, size limiet, of filename sanitization
Fix: valideer MIME type, beperk bestandsgrootte, en sanitize de filename

```python
# Voor (Flask):
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join('uploads', f.filename))
    return 'OK'

# Na (Flask):
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f.content_length and f.content_length > MAX_FILE_SIZE:
        return 'Bestand te groot', 413
    filename = secure_filename(f.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return 'Niet-toegestaan bestandstype', 400
    f.save(os.path.join('uploads', filename))
    return 'OK'
```

```javascript
// Voor (Express/Multer):
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('OK');
});

// Na (Express/Multer):
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/gif', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Niet-toegestaan bestandstype'));
    }
    cb(null, true);
  }
});
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('OK');
});
```

## Password Hashing
Zoek: wachtwoorden gehasht met MD5 of SHA in plaats van een password hashing algoritme
Fix: gebruik bcrypt, argon2 of een ander password-specifiek hashing algoritme

```python
# Voor:
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# Na:
from passlib.hash import bcrypt
hashed = bcrypt.hash(password)
# Verificatie:
is_valid = bcrypt.verify(password, hashed)
```

```javascript
// Voor (Node.js):
const hash = crypto.createHash('sha256').update(password).digest('hex');

// Na (Node.js):
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
// Verificatie:
const isValid = await bcrypt.compare(password, hash);
```

```java
// Voor:
MessageDigest md = MessageDigest.getInstance("MD5");
String hash = DatatypeConverter.printHexBinary(md.digest(password.getBytes()));

// Na:
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);
// Verificatie:
boolean isValid = encoder.matches(password, hash);
```
