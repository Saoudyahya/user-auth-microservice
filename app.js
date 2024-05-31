const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
const { Eureka } = require('eureka-js-client');

const app = express();
const PORT = process.env.PORT || 3001;

mongoose.connect('mongodb://localhost:27017/user_management');

app.use(bodyParser.json());
app.use(cors());

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  username: String,
  email: String,
  password: String,
  userRole: { type: mongoose.Schema.Types.ObjectId, ref: 'UserRole' }
});

const userRoleSchema = new mongoose.Schema({
  roleName: String
});

const User = mongoose.model('User', userSchema);
const UserRole = mongoose.model('UserRole', userRoleSchema);

const generateSecretKey = () => {
  return crypto.randomBytes(32).toString('hex');
}

const JWT_SECRET = generateSecretKey();

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username }).populate('userRole');
    console.log(user);
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }
    
    const userData = {
      id: user._id,
      username: user.username,
      role: user.userRole.roleName
    };
    
    const token = jwt.sign(userData, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
  });
}

app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully', user: req.user });
});

// User and Role management routes remain unchanged
app.post('/api/users', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      userRole: req.body.userRole
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().populate('userRole');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    res.json(deletedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/roles', async (req, res) => {
  try {
    const role = await UserRole.create(req.body);
    res.json(role);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/roles', async (req, res) => {
  try {
    const roles = await UserRole.find();
    res.json(roles);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/roles/:id', async (req, res) => {
  try {
    const updatedRole = await UserRole.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedRole);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/roles/:id', async (req, res) => {
  try {
    const deletedRole = await UserRole.findByIdAndDelete(req.params.id);
    res.json(deletedRole);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const eurekaClient = new Eureka({
  instance: {
    app: 'User-Auth-service',
    hostName: 'localhost',
    ipAddr: '127.0.0.1',
    statusPageUrl: `http://localhost:${PORT}`,
    port: {
      '$': PORT,
      '@enabled': true,
    },
    vipAddress: 'User-Auth-service',
    dataCenterInfo: {
      '@class': 'com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo',
      name: 'MyOwn',
    },
  },
  eureka: {
    host: 'localhost',
    port: 8761,
    servicePath: '/eureka/apps/',
  },
});

eurekaClient.start((error) => {
  console.log(error || 'Eureka client started successfully');
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
