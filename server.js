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
const crypto = require('crypto');
const Razorpay = require('razorpay');

dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();
const server = http.createServer(app);

// ─── Razorpay (Test Mode by default — swap keys in .env when live) ────────────
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret'
});

// ─── Owner Dashboard Secret (you, the developer, only) ────────────────────────
const OWNER_SECRET = process.env.OWNER_SECRET || 'change_this_owner_secret_now';

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
  // 'base' = menu-only (no ordering/kitchen/invoices), 'premium' = full system, 'paused' = suspended
  plan: { type: String, enum: ['base', 'premium', 'paused'], default: 'base' },
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

// Each table gets a random unguessable code, plus a human-friendly label for staff
const TableSchema = new mongoose.Schema({
  restaurantId: { type: String, required: true, index: true },
  tableCode: { type: String, required: true, unique: true }, // e.g. tbl_x7y2k9
  label: { type: String, required: true }, // e.g. "Table 5"
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  restaurantId: { type: String, required: true, index: true },
  tableCode: { type: String, default: '' },     // random secure code used to place order
  tableNumber: { type: String, required: true }, // human-friendly label, kept for display compatibility
  customerName: { type: String, default: '' },
  customerPhone: { type: String, default: '' },
  items: [{
    menuItemId: String,
    name: String,
    price: Number,
    quantity: Number
  }],
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'done'], default: 'pending' },
  paymentStatus: { type: String, enum: ['unpaid', 'paid', 'failed'], default: 'unpaid' },
  razorpayOrderId: { type: String, default: '' },
  razorpayPaymentId: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const InvoiceSchema = new mongoose.Schema({
  restaurantId: { type: String, required: true, index: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
  restaurantName: { type: String, required: true },
  customerName: { type: String, default: '' },
  customerPhone: { type: String, default: '' },
  tableNumber: { type: String, required: true },
  items: [{
    name: String,
    price: Number,
    quantity: Number,
    subtotal: Number
  }],
  total: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Restaurant = mongoose.model('Restaurant', RestaurantSchema);
const MenuItem = mongoose.model('MenuItem', MenuItemSchema);
const Table = mongoose.model('Table', TableSchema);
const Order = mongoose.model('Order', OrderSchema);
const Invoice = mongoose.model('Invoice', InvoiceSchema);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateRestaurantId() {
  return 'rest_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

// Random, unguessable table code — e.g. tbl_x7y2k9p3
function generateTableCode() {
  return 'tbl_' + crypto.randomBytes(6).toString('hex');
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

// Blocks access entirely if a restaurant's plan is 'paused'
async function requireActiveMiddleware(req, res, next) {
  try {
    const restaurant = await Restaurant.findOne({ restaurantId: req.restaurantId }).select('plan');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    if (restaurant.plan === 'paused') {
      return res.status(403).json({ error: 'This account is currently paused. Please contact support.' });
    }
    req.plan = restaurant.plan;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Server error checking account status' });
  }
}

// Blocks ordering/kitchen/invoice features for restaurants on the 'base' plan
async function requirePremiumMiddleware(req, res, next) {
  try {
    const restaurant = await Restaurant.findOne({ restaurantId: req.restaurantId }).select('plan');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    if (restaurant.plan === 'paused') {
      return res.status(403).json({ error: 'This account is currently paused. Please contact support.' });
    }
    if (restaurant.plan !== 'premium') {
      return res.status(403).json({ error: 'This feature requires a Premium plan. Please upgrade to enable ordering.' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: 'Server error checking plan' });
  }
}

// Protects the owner-only dashboard routes (you, the developer)
function ownerAuthMiddleware(req, res, next) {
  const key = req.headers['x-owner-key'];
  if (!key || key !== OWNER_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
// Simple, reliable email format check — catches the common "forgot the @" or "no domain" mistakes
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post('/api/register', async (req, res) => {
  try {
    let { name, email, password } = req.body;
    name = (name || '').trim();
    email = (email || '').trim();

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Please fill in your restaurant name, email, and password.' });
    }
    if (name.length < 2) {
      return res.status(400).json({ error: 'Restaurant name is too short.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address (e.g. name@example.com).' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const existing = await Restaurant.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'An account with this email already exists. Try logging in instead.' });

    const hashed = await bcrypt.hash(password, 12);
    const restaurantId = generateRestaurantId();
    const restaurant = await Restaurant.create({
      name,
      email: email.toLowerCase(),
      password: hashed,
      restaurantId,
      theme: { themeName: 'classic', brandColor: '#d4af37', font: 'playfair', tagline: '', hours: '', logoUrl: '' },
      plan: 'base'
    });

    const token = signToken({ restaurantId: restaurant.restaurantId, email: restaurant.email });
    res.status(201).json({
      token,
      restaurant: {
        id: restaurant.restaurantId,
        name: restaurant.name,
        email: restaurant.email,
        theme: restaurant.theme,
        setupComplete: restaurant.setupComplete,
        plan: restaurant.plan
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
        setupComplete: restaurant.setupComplete,
        plan: restaurant.plan
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
      setupComplete: restaurant.setupComplete,
      plan: restaurant.plan
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

// ─── Table Routes (secure random codes) ───────────────────────────────────────
app.get('/api/admin/tables', authMiddleware, async (req, res) => {
  try {
    const tables = await Table.find({ restaurantId: req.restaurantId }).sort({ createdAt: 1 });
    res.json(tables);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching tables' });
  }
});

app.post('/api/admin/tables', authMiddleware, async (req, res) => {
  try {
    const { label } = req.body;
    if (!label) return res.status(400).json({ error: 'Table label is required (e.g. "Table 5")' });

    let tableCode;
    let attempts = 0;
    do {
      tableCode = generateTableCode();
      attempts++;
    } while (await Table.findOne({ tableCode }) && attempts < 5);

    const table = await Table.create({
      restaurantId: req.restaurantId,
      tableCode,
      label
    });
    res.status(201).json(table);
  } catch (err) {
    console.error('Create table error:', err);
    res.status(500).json({ error: 'Server error creating table' });
  }
});

app.put('/api/admin/tables/:id', authMiddleware, async (req, res) => {
  try {
    const { label, active } = req.body;
    const update = {};
    if (label !== undefined) update.label = label;
    if (active !== undefined) update.active = active;

    const table = await Table.findOneAndUpdate(
      { _id: req.params.id, restaurantId: req.restaurantId },
      { $set: update },
      { new: true }
    );
    if (!table) return res.status(404).json({ error: 'Table not found' });
    res.json(table);
  } catch (err) {
    res.status(500).json({ error: 'Server error updating table' });
  }
});

app.delete('/api/admin/tables/:id', authMiddleware, async (req, res) => {
  try {
    const table = await Table.findOneAndDelete({ _id: req.params.id, restaurantId: req.restaurantId });
    if (!table) return res.status(404).json({ error: 'Table not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error deleting table' });
  }
});

// QR code for a specific table, using its secure random code
app.get('/api/admin/tables/:id/qr', authMiddleware, async (req, res) => {
  try {
    const table = await Table.findOne({ _id: req.params.id, restaurantId: req.restaurantId });
    if (!table) return res.status(404).json({ error: 'Table not found' });

    const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const menuUrl = `${BASE_URL}/menu/menu.html?restaurant=${req.restaurantId}&t=${table.tableCode}`;

    const qrDataUrl = await QRCode.toDataURL(menuUrl, {
      width: 400,
      margin: 2,
      color: { dark: '#1b1c1c', light: '#fbf9f8' }
    });

    res.json({ qrDataUrl, menuUrl, label: table.label });
  } catch (err) {
    console.error('Table QR error:', err);
    res.status(500).json({ error: 'Server error generating table QR code' });
  }
});

// ─── Public Menu Route ────────────────────────────────────────────────────────
app.get('/api/menu/:restaurantId', async (req, res) => {
  try {
    const restaurant = await Restaurant.findOne({ restaurantId: req.params.restaurantId }).select('-password');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });

    if (restaurant.plan === 'paused') {
      return res.status(403).json({ error: 'This restaurant is temporarily unavailable.' });
    }

    const items = await MenuItem.find({ restaurantId: req.params.restaurantId, available: true }).sort({ category: 1, createdAt: 1 });

    // Resolve table code (secure) to a human-friendly label, if provided
    let tableLabel = null;
    const tableCode = req.query.t;
    if (tableCode) {
      const table = await Table.findOne({ restaurantId: req.params.restaurantId, tableCode, active: true });
      if (table) tableLabel = table.label;
    }

    res.json({
      restaurant: {
        id: restaurant.restaurantId,
        name: restaurant.name,
        theme: restaurant.theme,
        plan: restaurant.plan // 'base' restaurants show menu only, frontend hides cart/order UI
      },
      items,
      tableLabel,
      razorpayKeyId: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder'
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching menu' });
  }
});

// ─── Payment Routes (Razorpay) ─────────────────────────────────────────────────
// Step 1: Create a Razorpay order for the cart total (before the food order is saved)
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const { restaurantId, total } = req.body;
    if (!restaurantId || !total) {
      return res.status(400).json({ error: 'restaurantId and total are required' });
    }

    const restaurant = await Restaurant.findOne({ restaurantId });
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    if (restaurant.plan !== 'premium') {
      return res.status(403).json({ error: 'Ordering is not enabled for this restaurant yet.' });
    }

    const razorpayOrder = await razorpay.orders.create({
      amount: Math.round(total * 100), // paise
      currency: 'INR',
      receipt: 'rcpt_' + Date.now()
    });

    res.json({
      razorpayOrderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
      keyId: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder'
    });
  } catch (err) {
    console.error('Razorpay create-order error:', err);
    res.status(500).json({ error: 'Could not initiate payment. Please try again.' });
  }
});

// Step 2: Verify payment signature, then create the actual food order + invoice
app.post('/api/order', async (req, res) => {
  try {
    const {
      restaurantId, tableCode, tableNumber, customerName, customerPhone, items,
      razorpayOrderId, razorpayPaymentId, razorpaySignature
    } = req.body;

    if (!restaurantId || !tableNumber || !items || !items.length) {
      return res.status(400).json({ error: 'restaurantId, tableNumber, and items are required' });
    }
    if (!customerName || !customerPhone) {
      return res.status(400).json({ error: 'Customer name and phone number are required' });
    }

    const restaurant = await Restaurant.findOne({ restaurantId });
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    if (restaurant.plan !== 'premium') {
      return res.status(403).json({ error: 'Ordering is not enabled for this restaurant yet.' });
    }

    // Verify Razorpay payment signature to confirm payment actually happened
    let paymentStatus = 'unpaid';
    if (razorpayOrderId && razorpayPaymentId && razorpaySignature) {
      const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret')
        .update(`${razorpayOrderId}|${razorpayPaymentId}`)
        .digest('hex');

      if (expectedSignature === razorpaySignature) {
        paymentStatus = 'paid';
      } else {
        return res.status(400).json({ error: 'Payment verification failed. Please try again.' });
      }
    } else {
      return res.status(400).json({ error: 'Payment information missing. Please complete payment first.' });
    }

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    const order = await Order.create({
      restaurantId,
      tableCode: tableCode || '',
      tableNumber,
      customerName,
      customerPhone,
      items,
      total: parseFloat(total.toFixed(2)),
      paymentStatus,
      razorpayOrderId: razorpayOrderId || '',
      razorpayPaymentId: razorpayPaymentId || ''
    });

    // Generate invoice immediately so it's ready for the kitchen/admin to print
    const invoice = await Invoice.create({
      restaurantId,
      orderId: order._id,
      restaurantName: restaurant.name,
      customerName,
      customerPhone,
      tableNumber,
      items: items.map(i => ({
        name: i.name,
        price: i.price,
        quantity: i.quantity,
        subtotal: parseFloat((i.price * i.quantity).toFixed(2))
      })),
      total: order.total
    });

    io.to(`kitchen_${restaurantId}`).emit('new_order', {
      _id: order._id,
      tableNumber: order.tableNumber,
      customerName: order.customerName,
      customerPhone: order.customerPhone,
      items: order.items,
      total: order.total,
      status: order.status,
      paymentStatus: order.paymentStatus,
      createdAt: order.createdAt
    });

    res.status(201).json({ success: true, orderId: order._id, invoiceId: invoice._id });
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

// ─── Invoice Routes ─────────────────────────────────────────────────────────────
app.get('/api/admin/invoices', authMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const invoices = await Invoice.find({
      restaurantId: req.restaurantId,
      createdAt: { $gte: today }
    }).sort({ createdAt: -1 });
    res.json(invoices);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching invoices' });
  }
});

app.get('/api/admin/invoices/:id', authMiddleware, async (req, res) => {
  try {
    const invoice = await Invoice.findOne({ _id: req.params.id, restaurantId: req.restaurantId });
    if (!invoice) return res.status(404).json({ error: 'Invoice not found' });
    res.json(invoice);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching invoice' });
  }
});

// Kitchen screen can also fetch an invoice by order ID for quick "Generate Bill" use
app.get('/api/kitchen/invoice-by-order/:orderId', async (req, res) => {
  try {
    const invoice = await Invoice.findOne({ orderId: req.params.orderId });
    if (!invoice) return res.status(404).json({ error: 'Invoice not found for this order' });
    res.json(invoice);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching invoice' });
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

// ─── Owner Dashboard Routes (developer-only, protected by OWNER_SECRET) ───────
// View all restaurants and their current plan
app.get('/api/owner/restaurants', ownerAuthMiddleware, async (req, res) => {
  try {
    const restaurants = await Restaurant.find().select('-password').sort({ createdAt: -1 });
    res.json(restaurants);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching restaurants' });
  }
});

// Change a restaurant's plan: 'base', 'premium', or 'paused'
app.put('/api/owner/restaurants/:restaurantId/plan', ownerAuthMiddleware, async (req, res) => {
  try {
    const { plan } = req.body;
    if (!['base', 'premium', 'paused'].includes(plan)) {
      return res.status(400).json({ error: 'Plan must be base, premium, or paused' });
    }
    const restaurant = await Restaurant.findOneAndUpdate(
      { restaurantId: req.params.restaurantId },
      { $set: { plan } },
      { new: true }
    ).select('-password');
    if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });
    res.json(restaurant);
  } catch (err) {
    res.status(500).json({ error: 'Server error updating plan' });
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
    if (restaurant.plan === 'paused') return res.status(403).json({ error: 'Account is paused' });
    if (restaurant.plan !== 'premium') return res.status(403).json({ error: 'Kitchen screen requires a Premium plan' });

    res.json({ restaurantId: decoded.restaurantId, name: restaurant.name, plan: restaurant.plan });
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