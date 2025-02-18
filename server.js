const express = require('express');
const sqlite3 = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 5000;
const db = new sqlite3('./database.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Initialisation de la base de données
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Ajouter la colonne 'is_archived' si elle n'existe pas
const columns = db.prepare("PRAGMA table_info(messages)").all();
if (!columns.some(col => col.name === 'is_archived')) {
    db.exec(`ALTER TABLE messages ADD COLUMN is_archived INTEGER DEFAULT 0`);
    console.log("✅ Colonne 'is_archived' ajoutée.");
}

// Création d'un compte admin initial si inexistant
const adminExists = db.prepare('SELECT * FROM users WHERE role = ?').get('admin');
if (!adminExists) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run('admin@admin.com', hashedPassword, 'admin');
    console.log('🔑 Compte admin initial créé : admin@admin.com / admin123');
}

// Middleware d'authentification
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Accès non autorisé' });

    jwt.verify(token, 'secret', (err, user) => {
        if (err) return res.status(403).json({ message: 'Token invalide' });
        req.user = user;
        next();
    });
}

// Middleware de vérification admin
function isAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Accès réservé aux administrateurs' });
    }
    next();
}

// Inscription utilisateur (côté utilisateur)
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email et mot de passe requis.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hashedPassword);
        res.json({ message: 'Inscription réussie.' });
    } catch (error) {
        res.status(400).json({ message: 'Email déjà utilisé.' });
    }
});

// Connexion utilisateur
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });

    bcrypt.compare(password, user.password, (err, valid) => {
        if (valid) {
            const token = jwt.sign({ email: user.email, role: user.role }, 'secret', { expiresIn: '2h' });
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
        }
    });
});

// Créer un utilisateur (côté admin)
app.post('/admin/addUser', authenticateToken, isAdmin, async (req, res) => {
    const { email, password, role } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email et mot de passe requis.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(email, hashedPassword, role || 'user');
        res.json({ message: `Utilisateur ${email} ajouté avec succès.` });
    } catch (error) {
        res.status(400).json({ message: 'Cet email est déjà utilisé.' });
    }
});

// Charger les messages de l'utilisateur
app.get('/inbox', authenticateToken, (req, res) => {
    const messages = db.prepare(`
        SELECT id, sender, subject, content, timestamp 
        FROM messages 
        WHERE recipient = ? AND is_archived = 0
    `).all(req.user.email);
    res.json(messages);
});


// Envoyer un message
app.post('/send', authenticateToken, (req, res) => {
    const { recipient, subject, content } = req.body;
    const sender = req.user.email;

    const recipientExists = db.prepare('SELECT email FROM users WHERE email = ?').get(recipient);
    if (!recipientExists) {
        return res.status(404).json({ message: 'Destinataire introuvable.' });
    }

    const stmt = db.prepare('INSERT INTO messages (sender, recipient, subject, content) VALUES (?, ?, ?, ?)');
    stmt.run(sender, recipient, subject, content);
    res.json({ message: 'Message envoyé.' });
});

// Récupérer tous les utilisateurs (admin only)
app.get('/admin/users', authenticateToken, isAdmin, (req, res) => {
    const users = db.prepare('SELECT email, role FROM users').all();
    res.json(users);
});

// Promouvoir un utilisateur en admin
app.put('/admin/promote/:email', authenticateToken, isAdmin, (req, res) => {
    const { email } = req.params;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    db.prepare('UPDATE users SET role = ? WHERE email = ?').run('admin', email);
    res.json({ message: `L'utilisateur ${email} est maintenant administrateur.` });
});

// Supprimer un utilisateur (admin only)
app.delete('/admin/users/:email', authenticateToken, isAdmin, (req, res) => {
    const { email } = req.params;
    const result = db.prepare('DELETE FROM users WHERE email = ?').run(email);
    if (result.changes > 0) {
        res.json({ message: `Utilisateur ${email} supprimé.` });
    } else {
        res.status(404).json({ message: 'Utilisateur introuvable.' });
    }
});

// Route pour se connecter en tant qu'un autre utilisateur
app.post('/admin/switch', authenticateToken, isAdmin, (req, res) => {
    const { email } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
        return res.status(404).json({ message: 'Utilisateur introuvable' });
    }

    const newToken = jwt.sign({ email: user.email, role: user.role }, 'secret', { expiresIn: '1h' });
    res.json({ newToken });
});

// Supprimer un message
app.delete('/messages/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const result = db.prepare('DELETE FROM messages WHERE id = ?').run(id);
    if (result.changes > 0) {
        res.json({ message: 'Message supprimé.' });
    } else {
        res.status(404).json({ message: 'Message introuvable.' });
    }
});

// Récupérer les infos de l'utilisateur connecté
app.get('/me', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT email, role FROM users WHERE email = ?').get(req.user.email);
    if (user) {
        res.json(user);
    } else {
        res.status(404).json({ message: 'Utilisateur introuvable' });
    }
});

// Charger les messages envoyés par l'utilisateur
app.get('/sent', authenticateToken, (req, res) => {
    const stmt = db.prepare('SELECT recipient, subject, content, timestamp FROM messages WHERE sender = ?');
    const messages = stmt.all(req.user.email);
    res.json(messages);
});

// 📦 Archiver un message
async function archiveMessage(id) {
    console.log("Tentative d'archivage du message ID :", id);
    if (!confirm("Archiver ce message ?")) return;
    
    try {
        const res = await fetch(`http://localhost:5000/messages/${id}/archive`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await res.json();
        console.log("Réponse de l'API :", data);

        alert(data.message);
        loadMessages('inbox');
        loadMessages('archive');
    } catch (error) {
        console.error("Erreur d'archivage :", error);
    }
}


// 🗑️ Supprimer un message
async function deleteMessage(id) {
    console.log("Tentative de suppression du message ID :", id);
    if (!confirm("Supprimer ce message définitivement ?")) return;
    
    try {
        const res = await fetch(`http://localhost:5000/messages/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await res.json();
        console.log("Réponse de l'API :", data);

        alert(data.message);
        loadMessages('inbox');
        loadMessages('archive');
    } catch (error) {
        console.error("Erreur de suppression :", error);
    }
}

// Archiver un message
app.put('/messages/:id/archive', authenticateToken, (req, res) => {
    const { id } = req.params;
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
    if (!message) return res.status(404).json({ message: 'Message introuvable.' });

    // Déplacer le message dans l'archive (ajout d'un champ is_archived)
    db.prepare('UPDATE messages SET is_archived = 1 WHERE id = ?').run(id);
    res.json({ message: 'Message archivé avec succès.' });
});

app.get('/archive', authenticateToken, (req, res) => {
    const messages = db.prepare(`
        SELECT id, sender, subject, content, timestamp 
        FROM messages 
        WHERE recipient = ? AND is_archived = 1
    `).all(req.user.email);
    res.json(messages);
});


app.put('/messages/:id/archive', authenticateToken, (req, res) => {
    const { id } = req.params;
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
    if (!message) return res.status(404).json({ message: 'Message introuvable.' });

    db.prepare('UPDATE messages SET is_archived = 1 WHERE id = ?').run(id);
    res.json({ message: 'Message archivé avec succès.' });
});

// Modifier le mot de passe d'un utilisateur (admin only)
app.post('/change-password', async (req, res) => {
    const { oldPassword, newPassword, email } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).send('Utilisateur non trouvé.');
    }

    if (user.password !== oldPassword) {
        return res.status(400).send('Ancien mot de passe incorrect.');
    }

    user.password = newPassword;
    return res.status(200).send('Mot de passe changé avec succès.');
});

// Modifier l'email d'un utilisateur
app.put('/admin/editEmail', authenticateToken, isAdmin, (req, res) => {
    const { oldEmail, newEmail } = req.body;

    if (!oldEmail || !newEmail) {
        return res.status(400).json({ message: 'Ancien et nouvel email requis.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(oldEmail);
    if (!user) {
        return res.status(404).json({ message: 'Utilisateur introuvable.' });
    }

    try {
        db.prepare('UPDATE users SET email = ? WHERE email = ?').run(newEmail, oldEmail);
        res.json({ message: `Email modifié avec succès : ${oldEmail} → ${newEmail}` });
    } catch (error) {
        res.status(400).json({ message: 'Cet email est déjà utilisé.' });
    }
});


// Lancer le serveur
app.listen(PORT, () => console.log(`🚀 Serveur en ligne sur http://localhost:${PORT}`));
