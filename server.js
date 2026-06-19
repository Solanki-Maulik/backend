require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const dns = require('dns');

dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();
const server = http.createServer(app);

// ─── Socket.io ────────────────────────────────────────────────────────────────
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }
});

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── MongoDB Models ───────────────────────────────────────────────────────────
const RestaurantSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  restaurantId: { type: String, unique: true },
  theme: {
    themeName: { type: String, default: 'classic' },
    brandColor: { type: String, default: '#d4af37' },
    font: { type: String, default: 'playfair' },
    tagline: { type: String, default: '' },
    hours: { type: String, default: '' },
    logoUrl: { type: String, default: '' }
  },
  setupComplete: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const MenuItemSchema = new mongoose.Schema({
  restaurantId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  available: { type: Boolean, default: true },
  imageUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  restaurantId: { type: String, required: true, index: true },
  tableNumber: { type: String, required: true },
  items: [{
    menuItemId: String,
    name: String,
    price: Number,
    quantity: Number
  }],
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'done'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Restaurant = mongoose.model('Restaurant', RestaurantSchema);
const MenuItem = mongoose.model('MenuItem', MenuItemSchema);
const Order = mongoose.model('Order', OrderSchema);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateRestaurantId() {
  return 'rest_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'qrmenu_secret_key', { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'qrmenu_secret_key');
    req.restaurantId = decoded.restaurantId;
    req.email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    const existing = await Restaurant.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 12);
    const restaurantId = generateRestaurantId();
    const restaurant = await Restaurant.create({
      name,
      email: email.toLowerCase(),
      password: hashed,
      restaurantId,
      theme: { themeName: 'classic', brandColor: '#d4af37', font: 'playfair', tagline: '', hours: '', logoUrl: '' }
    });

    const token = signToken({ restaurantId: restaurant.restaurantId, email: restaurant.email });
    res.status(201).json({
      token,
      restaurant: {
        id: restaurant.restaurantId,
        name: restaurant.name,
        email: restaurant.email,
        theme: restaurant.theme,
        setupComplete: restaurant.setupComplete
      }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const restaurant = await Restaurant.findOne({ email: email.toLowerCase() });
    if (!restaurant) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, restaurant.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ restaurantId: restaurant.restaurantId, email: restaurant.email });
    res.json({
      token,
      restaurant: {
        id: restaurant.restaurantId,
        name: restaurant.name,
        email: restaurant.email,
        theme: restaurant.theme,
        setupComplete: restaurant.setupComplete
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const restaurant = await Restaurant.findOne({ restaurantId: req.restaurantId }).select('-password');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    res.json({
      id: restaurant.restaurantId,
      name: restaurant.name,
      email: restaurant.email,
      theme: restaurant.theme,
      setupComplete: restaurant.setupComplete
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Theme Routes ─────────────────────────────────────────────────────────────
app.put('/api/admin/theme', authMiddleware, async (req, res) => {
  try {
    const { themeName, brandColor, font, tagline, hours, logoUrl } = req.body;
    const update = {};
    if (themeName !== undefined) update['theme.themeName'] = themeName;
    if (brandColor !== undefined) update['theme.brandColor'] = brandColor;
    if (font !== undefined) update['theme.font'] = font;
    if (tagline !== undefined) update['theme.tagline'] = tagline;
    if (hours !== undefined) update['theme.hours'] = hours;
    if (logoUrl !== undefined) update['theme.logoUrl'] = logoUrl;

    const restaurant = await Restaurant.findOneAndUpdate(
      { restaurantId: req.restaurantId },
      { $set: update },
      { new: true }
    ).select('-password');

    res.json({ theme: restaurant.theme });
  } catch (err) {
    console.error('Theme update error:', err);
    res.status(500).json({ error: 'Server error updating theme' });
  }
});

app.put('/api/admin/setup-complete', authMiddleware, async (req, res) => {
  try {
    await Restaurant.findOneAndUpdate(
      { restaurantId: req.restaurantId },
      { $set: { setupComplete: true } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Menu Routes ──────────────────────────────────────────────────────────────
app.get('/api/admin/menu', authMiddleware, async (req, res) => {
  try {
    const items = await MenuItem.find({ restaurantId: req.restaurantId }).sort({ category: 1, createdAt: 1 });
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching menu' });
  }
});

app.post('/api/admin/menu', authMiddleware, async (req, res) => {
  try {
    const { name, description, price, category, available, imageUrl } = req.body;
    if (!name || price === undefined || !category) {
      return res.status(400).json({ error: 'Name, price, and category are required' });
    }
    const item = await MenuItem.create({
      restaurantId: req.restaurantId,
      name,
      description: description || '',
      price: parseFloat(price),
      category,
      available: available !== undefined ? available : true,
      imageUrl: imageUrl || ''
    });
    res.status(201).json(item);
  } catch (err) {
    console.error('Create menu item error:', err);
    res.status(500).json({ error: 'Server error creating menu item' });
  }
});

app.put('/api/admin/menu/:id', authMiddleware, async (req, res) => {
  try {
    const { name, description, price, category, available, imageUrl } = req.body;
    const item = await MenuItem.findOneAndUpdate(
      { _id: req.params.id, restaurantId: req.restaurantId },
      { $set: { name, description, price: parseFloat(price), category, available, imageUrl } },
      { new: true }
    );
    if (!item) return res.status(404).json({ error: 'Menu item not found' });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: 'Server error updating menu item' });
  }
});

app.delete('/api/admin/menu/:id', authMiddleware, async (req, res) => {
  try {
    const item = await MenuItem.findOneAndDelete({ _id: req.params.id, restaurantId: req.restaurantId });
    if (!item) return res.status(404).json({ error: 'Menu item not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error deleting menu item' });
  }
});

// ─── Public Menu Route ────────────────────────────────────────────────────────
app.get('/api/menu/:restaurantId', async (req, res) => {
  try {
    const restaurant = await Restaurant.findOne({ restaurantId: req.params.restaurantId }).select('-password');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });

    const items = await MenuItem.find({ restaurantId: req.params.restaurantId, available: true }).sort({ category: 1, createdAt: 1 });

    res.json({
      restaurant: {
        id: restaurant.restaurantId,
        name: restaurant.name,
        theme: restaurant.theme
      },
      items
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching menu' });
  }
});

// ─── Order Routes ─────────────────────────────────────────────────────────────
app.post('/api/order', async (req, res) => {
  try {
    const { restaurantId, tableNumber, items } = req.body;
    if (!restaurantId || !tableNumber || !items || !items.length) {
      return res.status(400).json({ error: 'restaurantId, tableNumber, and items are required' });
    }

    const restaurant = await Restaurant.findOne({ restaurantId });
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    const order = await Order.create({
      restaurantId,
      tableNumber,
      items,
      total: parseFloat(total.toFixed(2))
    });

    io.to(`kitchen_${restaurantId}`).emit('new_order', {
      _id: order._id,
      tableNumber: order.tableNumber,
      items: order.items,
      total: order.total,
      status: order.status,
      createdAt: order.createdAt
    });

    res.status(201).json({ success: true, orderId: order._id });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Server error creating order' });
  }
});

app.get('/api/admin/orders', authMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const orders = await Order.find({
      restaurantId: req.restaurantId,
      createdAt: { $gte: today }
    }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching orders' });
  }
});

app.put('/api/admin/orders/:id', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, restaurantId: req.restaurantId },
      { $set: { status } },
      { new: true }
    );
    if (!order) return res.status(404).json({ error: 'Order not found' });

    io.to(`kitchen_${req.restaurantId}`).emit('order_updated', {
      _id: order._id,
      status: order.status
    });

    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Server error updating order' });
  }
});

// ─── QR Code Route ────────────────────────────────────────────────────────────
app.get('/api/admin/qr', authMiddleware, async (req, res) => {
  try {
    const table = req.query.table || '1';
    const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const menuUrl = `${BASE_URL}/menu/menu.html?restaurant=${req.restaurantId}&table=${table}`;

    const qrDataUrl = await QRCode.toDataURL(menuUrl, {
      width: 400,
      margin: 2,
      color: { dark: '#1b1c1c', light: '#fbf9f8' }
    });

    res.json({ qrDataUrl, menuUrl });
  } catch (err) {
    console.error('QR error:', err);
    res.status(500).json({ error: 'Server error generating QR code' });
  }
});

// ─── Kitchen Auth Route ───────────────────────────────────────────────────────
app.get('/api/kitchen/verify', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'qrmenu_secret_key');
    const restaurant = await Restaurant.findOne({ restaurantId: decoded.restaurantId }).select('-password');
    if (!restaurant) return res.status(404).json({ error: 'Not found' });

    res.json({ restaurantId: decoded.restaurantId, name: restaurant.name });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  socket.on('join_kitchen', (restaurantId) => {
    socket.join(`kitchen_${restaurantId}`);
  });

  socket.on('leave_kitchen', (restaurantId) => {
    socket.leave(`kitchen_${restaurantId}`);
  });
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ name: 'QR Menu SaaS API', version: '1.0.0' }));

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 10000,
  family: 4
})
.then(() => {
  console.log('✅ MongoDB connected');
  server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
})
.catch((err) => {
  console.error('❌ MongoDB connection failed:', err.message);
  process.exit(1);
});