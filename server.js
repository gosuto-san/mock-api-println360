import express from 'express';
import { Sequelize, DataTypes } from 'sequelize';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;

// Connexion PostgreSQL avec Sequelize
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST,
  dialect: 'postgres',
  dialectOptions: {
    ssl: false,
  },
});


// Modèle User
const User = sequelize.define('User', {
  name: { type: DataTypes.STRING, allowNull: false },
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
});

// Synchronisation de la base de données
sequelize.sync().then(() => console.log('✅ Base de données synchronisée avec PostgreSQL'));

app.use(express.json());
app.use(cors());

// Middleware d'authentification
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Accès non autorisé' });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.userId = decoded.userId;
    next();
  });
};

// Inscription
app.post('/auth/register', async (req, res) => {
  const { name, username, password } = req.body;
  if (await User.findOne({ where: { username } })) {
    return res.status(400).json({ error: 'Utilisateur existant' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ name, username, password: hashedPassword });
  res.json({ message: 'Utilisateur créé', user });
});

// Connexion
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Nom d'utilisateur ou mot de passe incorrect" });
  }

  const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '1h' });
  res.json({ message: 'Connexion réussie', token });
});

// Profil utilisateur
app.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findByPk(req.userId, { attributes: { exclude: ['password'] } });
  res.json({ user });
});

// Liste des utilisateurs
app.get('/users/all', async (req, res) => {
  const users = await User.findAll({ attributes: { exclude: ['password'] } });
  res.json({ users });
});

// Détails d'un utilisateur
app.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id, { attributes: { exclude: ['password'] } });
  res.json({ user });
});

// Démarrage du serveur
app.listen(PORT, () => console.log(`✅ Serveur démarré sur http://localhost:${PORT}`));



