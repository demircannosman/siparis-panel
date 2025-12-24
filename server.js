const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors());
app.use(express.json());

// Database (JSON file)
const DB_FILE = path.join(__dirname, 'database.json');

function readDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (e) { console.error('DB read error:', e); }
  return { orders: [], sites: [], users: [{ id: 1, username: 'admin', password: 'admin123', role: 'admin' }], orderCounter: 1000 };
}

function writeDB(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); } 
  catch (e) { console.error('DB write error:', e); }
}

// Initialize DB
if (!fs.existsSync(DB_FILE)) writeDB(readDB());

// Simple JWT-like token
const tokens = new Map();
function generateToken(user) {
  const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
  tokens.set(token, { userId: user.id, username: user.username, role: user.role });
  return token;
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  const user = tokens.get(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// Auth Routes
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// Order Statuses
app.get('/api/order-statuses', (req, res) => {
  res.json([
    { value: 'Yeni', label: 'Yeni' },
    { value: 'Onaylı', label: 'Onaylı' },
    { value: 'Eksik', label: 'Eksik' },
    { value: 'İptal', label: 'İptal' },
    { value: 'Kargo', label: 'Kargo' },
    { value: 'Teslim', label: 'Teslim' },
    { value: 'Ulaşılamayan', label: 'Ulaşılamayan' },
    { value: 'İade', label: 'İade' }
  ]);
});

// Shipping Companies
app.get('/api/shipping-companies', (req, res) => {
  res.json([
    { id: 1, name: 'Yurtiçi Kargo' },
    { id: 2, name: 'Aras Kargo' },
    { id: 3, name: 'MNG Kargo' },
    { id: 4, name: 'PTT Kargo' },
    { id: 5, name: 'Sürat Kargo' }
  ]);
});

// Dashboard Stats
app.get('/api/dashboard/stats', authMiddleware, (req, res) => {
  const db = readDB();
  const today = new Date().toISOString().split('T')[0];
  const todayOrders = db.orders.filter(o => o.created_at && o.created_at.startsWith(today));
  res.json({
    todayOrders: todayOrders.length,
    pendingOrders: db.orders.filter(o => o.status === 'Yeni').length,
    totalOrders: db.orders.length,
    todayRevenue: todayOrders.reduce((sum, o) => sum + (parseFloat(o.total_amount) || 0), 0)
  });
});

// Orders Routes
app.get('/api/orders', authMiddleware, (req, res) => {
  const db = readDB();
  let orders = [...db.orders].reverse();
  
  if (req.query.status && req.query.status !== 'all') {
    orders = orders.filter(o => o.status === req.query.status);
  }
  if (req.query.search) {
    const s = req.query.search.toLowerCase();
    orders = orders.filter(o => 
      (o.customer_name || '').toLowerCase().includes(s) ||
      (o.customer_phone || '').includes(s) ||
      (o.order_number || '').toLowerCase().includes(s)
    );
  }
  
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const total = orders.length;
  const pages = Math.ceil(total / limit);
  orders = orders.slice((page - 1) * limit, page * limit);
  
  res.json({ orders, pagination: { page, pages, total } });
});

app.get('/api/orders/:id', authMiddleware, (req, res) => {
  const db = readDB();
  const order = db.orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json(order);
});

app.post('/api/public/orders', (req, res) => {
  const db = readDB();
  db.orderCounter = (db.orderCounter || 1000) + 1;
  const order = {
    id: db.orderCounter,
    order_number: 'SIP' + db.orderCounter,
    ...req.body,
    status: 'Yeni',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    history: [{ new_status: 'Yeni', created_at: new Date().toISOString() }]
  };
  db.orders.push(order);
  writeDB(db);
  res.json({ success: true, order_number: order.order_number, id: order.id });
});

app.put('/api/orders/:id', authMiddleware, (req, res) => {
  const db = readDB();
  const index = db.orders.findIndex(o => o.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Order not found' });
  
  const oldStatus = db.orders[index].status;
  db.orders[index] = { ...db.orders[index], ...req.body, updated_at: new Date().toISOString() };
  
  if (oldStatus !== req.body.status) {
    db.orders[index].history = db.orders[index].history || [];
    db.orders[index].history.push({ old_status: oldStatus, new_status: req.body.status, created_at: new Date().toISOString() });
  }
  
  writeDB(db);
  res.json({ success: true });
});

app.patch('/api/orders/:id/status', authMiddleware, (req, res) => {
  const db = readDB();
  const index = db.orders.findIndex(o => o.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Order not found' });
  
  const oldStatus = db.orders[index].status;
  db.orders[index].status = req.body.status;
  db.orders[index].updated_at = new Date().toISOString();
  db.orders[index].history = db.orders[index].history || [];
  db.orders[index].history.push({ old_status: oldStatus, new_status: req.body.status, created_at: new Date().toISOString() });
  
  writeDB(db);
  res.json({ success: true });
});

// Sites Routes
app.get('/api/sites', authMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.sites || []);
});

app.post('/api/sites', authMiddleware, (req, res) => {
  const db = readDB();
  const site = { id: Date.now(), ...req.body, created_at: new Date().toISOString() };
  db.sites = db.sites || [];
  db.sites.push(site);
  writeDB(db);
  res.json(site);
});

app.put('/api/sites/:id', authMiddleware, (req, res) => {
  const db = readDB();
  const index = (db.sites || []).findIndex(s => s.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Site not found' });
  db.sites[index] = { ...db.sites[index], ...req.body };
  writeDB(db);
  res.json(db.sites[index]);
});

app.delete('/api/sites/:id', authMiddleware, (req, res) => {
  const db = readDB();
  db.sites = (db.sites || []).filter(s => s.id !== parseInt(req.params.id));
  writeDB(db);
  res.json({ success: true });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Serve admin panel - TRY MULTIPLE PATHS
const possiblePaths = [
  path.join(__dirname, 'admin-panel', 'index.html'),
  path.join(__dirname, 'admin-panel.html'),
  path.join(__dirname, 'public', 'index.html'),
  path.join(__dirname, 'index.html')
];

app.get('/', (req, res) => {
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      console.log('Serving admin panel from:', p);
      return res.sendFile(p);
    }
  }
  // If no file found, serve inline HTML
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Sipariş Paneli</title><meta charset="UTF-8"></head>
    <body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0;">
      <div style="text-align:center;background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);">
        <h1>🚀 Sipariş API Çalışıyor!</h1>
        <p>Admin paneli için <code>admin-panel/index.html</code> dosyası gerekli.</p>
        <p style="margin-top:20px;"><a href="/api/health" style="color:blue;">API Health Check</a></p>
      </div>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`🚀 Sipariş Yönetim Sistemi: http://localhost:${PORT}`);
  console.log(`🔑 Giriş: admin / admin123`);
});
