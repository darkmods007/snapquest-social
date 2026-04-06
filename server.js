import express from 'express';
import cors from 'cors';
import multer from 'multer';
import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import session from 'express-session';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// CORS (utile si jamais tu as un autre frontend)
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public')); // ← ICI : sert ton frontend statique
app.use('/uploads', express.static('uploads'));

// Session
app.use(session({
    secret: 'snapquest_final_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const db = new sqlite3.Database('snapquest.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url TEXT,
        caption TEXT,
        user_id INTEGER,
        user_name TEXT,
        created_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.get('SELECT COUNT(*) as count FROM users', (err, result) => {
        if (result.count === 0) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run('INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)', 
                ['admin', hash, 'Administrateur', 'admin']);
            console.log('✅ Admin créé : admin / admin123');
        }
    });
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, unique);
    }
});
const upload = multer({ storage });

const isAuthenticated = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).json({ error: 'Non authentifié' });
};

const isAdmin = (req, res, next) => {
    if (req.session.role === 'admin') return next();
    res.status(403).json({ error: 'Admin requis' });
};

// ============ ROUTES ============

app.post('/api/auth/register', async (req, res) => {
    const { username, password, full_name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Champs requis' });
    
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)', 
        [username, hash, full_name || username, 'user'], 
        function(err) {
            if (err) return res.status(400).json({ error: 'Nom d\'utilisateur déjà pris' });
            req.session.userId = this.lastID;
            req.session.role = 'user';
            res.json({ user: { id: this.lastID, username, full_name: full_name || username, role: 'user' } });
        });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Identifiants invalides' });
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }
        
        req.session.userId = user.id;
        req.session.role = user.role;
        res.json({ user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json(null);
    db.get('SELECT id, username, full_name, role FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user) return res.json(null);
        res.json(user);
    });
});

app.get('/api/photos', isAuthenticated, (req, res) => {
    const isModOrAdmin = req.session.role === 'admin' || req.session.role === 'moderator';
    const query = isModOrAdmin ? 'SELECT * FROM photos ORDER BY created_date DESC' : 'SELECT * FROM photos WHERE user_id = ? ORDER BY created_date DESC';
    const params = isModOrAdmin ? [] : [req.session.userId];
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.post('/api/photos', isAuthenticated, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Image requise' });
    const image_url = `/uploads/${req.file.filename}`;
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        const userName = user ? user.full_name : 'Anonyme';
        db.run(
            'INSERT INTO photos (image_url, caption, user_id, user_name) VALUES (?, ?, ?, ?)',
            [image_url, req.body.caption || '', req.session.userId, userName],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID, image_url, caption: req.body.caption, user_name: userName });
            }
        );
    });
});

app.delete('/api/photos/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const isModOrAdmin = req.session.role === 'admin' || req.session.role === 'moderator';
    const query = isModOrAdmin ? 'DELETE FROM photos WHERE id = ?' : 'DELETE FROM photos WHERE id = ? AND user_id = ?';
    const params = isModOrAdmin ? [id] : [id, req.session.userId];
    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Photo supprimée' });
    });
});

app.get('/api/users', isAdmin, (req, res) => {
    db.all('SELECT id, username, full_name, role, created_at FROM users', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.put('/api/users/:id/role', isAdmin, (req, res) => {
    const { id } = req.params;
    const { role } = req.body;
    db.run('UPDATE users SET role = ? WHERE id = ?', [role, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Rôle mis à jour' });
    });
});

app.post('/api/users/invite', isAdmin, (req, res) => {
    const { username, role } = req.body;
    const defaultPassword = 'snapquest123';
    const hash = bcrypt.hashSync(defaultPassword, 10);
    db.run('INSERT OR IGNORE INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)', 
        [username, hash, username, role || 'user'], 
        function(err) {
            if (err) return res.status(400).json({ error: 'Nom d\'utilisateur déjà pris' });
            res.json({ message: 'Utilisateur invité', password: defaultPassword });
        });
});

// Servir le frontend pour toutes les autres routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
