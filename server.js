import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-degistir';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database
const defaultData = {
  users: [{ id: 1, username: 'admin', password: bcrypt.hashSync('admin123', 10), full_name: 'Sistem Yöneticisi', role: 'admin' }],
  sites: [],
  products: [],
  orders: [],
  order_history: [],
  shipping_companies: [
    { id: 1, name: 'Yurtiçi Kargo', code: 'yurtici' },
    { id: 2, name: 'Aras Kargo', code: 'aras' },
    { id: 3, name: 'MNG Kargo', code: 'mng' },
    { id: 4, name: 'PTT Kargo', code: 'ptt' },
    { id: 5, name: 'Sürat Kargo', code: 'surat' },
    { id: 6, name: 'Yol Kargo', code: 'yolkargo' }
  ],
  blocklist: [],
  message_templates: [
    { id: 1, name: 'Sipariş Onayı', type: 'whatsapp', content: 'Merhaba {{musteri_adi}}, {{siparis_no}} numaralı siparişiniz onaylanmıştır.' },
    { id: 2, name: 'Kargo Bilgisi', type: 'whatsapp', content: 'Siparişiniz kargoya verilmiştir. Takip No: {{kargo_takip}}' }
  ],
  counters: { orders: 700000000000, sites: 0, products: 0 }
};

const adapter = new JSONFile(join(__dirname, 'db.json'));
const db = new Low(adapter, defaultData);
await db.read();
if (!db.data) { db.data = defaultData; await db.write(); }

// Helpers
const generateId = (type) => { db.data.counters[type]++; return db.data.counters[type]; };
const generateOrderNumber = () => `7${Date.now().toString().slice(-8)}${Math.floor(Math.random()*1000).toString().padStart(3,'0')}`;

// Auth Middleware
const auth = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Geçersiz token' });
    req.user = user;
    next();
  });
};

// AUTH
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.data.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Hatalı giriş' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.data.users.find(u => u.id === req.user.id);
  res.json({ id: user.id, username: user.username, full_name: user.full_name, role: user.role });
});

// DASHBOARD
app.get('/api/dashboard/stats', auth, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const todayOrders = db.data.orders.filter(o => o.created_at?.startsWith(today)).length;
  const pendingOrders = db.data.orders.filter(o => ['Yeni', 'Eksik'].includes(o.status)).length;
  const todayRevenue = db.data.orders.filter(o => o.created_at?.startsWith(today) && !['İptal', 'Çöp'].includes(o.status)).reduce((s, o) => s + (o.total_amount || 0), 0);
  const statusCounts = {};
  db.data.orders.forEach(o => { statusCounts[o.status] = (statusCounts[o.status] || 0) + 1; });
  const recentOrders = db.data.orders.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 10).map(o => ({ ...o, site_name: db.data.sites.find(s => s.id === o.site_id)?.site_name }));
  res.json({ todayOrders, pendingOrders, totalOrders: db.data.orders.length, todayRevenue, statusCounts: Object.entries(statusCounts).map(([status, count]) => ({ status, count })), recentOrders });
});

// SITES
app.get('/api/sites', auth, (req, res) => res.json(db.data.sites.sort((a, b) => b.id - a.id)));
app.get('/api/sites/:id', auth, (req, res) => {
  const site = db.data.sites.find(s => s.id === parseInt(req.params.id));
  site ? res.json(site) : res.status(404).json({ error: 'Site bulunamadı' });
});
app.post('/api/sites', auth, async (req, res) => {
  const site = { id: generateId('sites'), ...req.body, status: 'active', created_at: new Date().toISOString() };
  db.data.sites.push(site);
  await db.write();
  res.json({ id: site.id, message: 'Site oluşturuldu' });
});
app.put('/api/sites/:id', auth, async (req, res) => {
  const i = db.data.sites.findIndex(s => s.id === parseInt(req.params.id));
  if (i === -1) return res.status(404).json({ error: 'Site bulunamadı' });
  db.data.sites[i] = { ...db.data.sites[i], ...req.body, updated_at: new Date().toISOString() };
  await db.write();
  res.json({ message: 'Site güncellendi' });
});
app.delete('/api/sites/:id', auth, async (req, res) => {
  db.data.sites = db.data.sites.filter(s => s.id !== parseInt(req.params.id));
  await db.write();
  res.json({ message: 'Site silindi' });
});

// PRODUCTS
app.get('/api/products', auth, (req, res) => {
  let products = db.data.products;
  if (req.query.site_id) products = products.filter(p => p.site_id === parseInt(req.query.site_id));
  res.json(products.map(p => ({ ...p, site_name: db.data.sites.find(s => s.id === p.site_id)?.site_name })).sort((a, b) => b.id - a.id));
});
app.post('/api/products', auth, async (req, res) => {
  const product = { id: generateId('products'), ...req.body, site_id: parseInt(req.body.site_id), status: 'active', created_at: new Date().toISOString() };
  db.data.products.push(product);
  await db.write();
  res.json({ id: product.id, message: 'Ürün oluşturuldu' });
});
app.put('/api/products/:id', auth, async (req, res) => {
  const i = db.data.products.findIndex(p => p.id === parseInt(req.params.id));
  if (i === -1) return res.status(404).json({ error: 'Ürün bulunamadı' });
  db.data.products[i] = { ...db.data.products[i], ...req.body };
  await db.write();
  res.json({ message: 'Ürün güncellendi' });
});
app.delete('/api/products/:id', auth, async (req, res) => {
  db.data.products = db.data.products.filter(p => p.id !== parseInt(req.params.id));
  await db.write();
  res.json({ message: 'Ürün silindi' });
});

// ORDERS
app.get('/api/orders', auth, (req, res) => {
  const { status, site_id, search, page = 1, limit = 20 } = req.query;
  let orders = [...db.data.orders];
  if (status && status !== 'all') orders = orders.filter(o => o.status === status);
  if (site_id) orders = orders.filter(o => o.site_id === parseInt(site_id));
  if (search) {
    const term = search.toLowerCase();
    orders = orders.filter(o => o.customer_name?.toLowerCase().includes(term) || o.customer_phone?.includes(term) || o.order_number?.includes(term));
  }
  orders = orders.map(o => ({ ...o, site_name: db.data.sites.find(s => s.id === o.site_id)?.site_name })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const total = orders.length;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  res.json({ orders: orders.slice(offset, offset + parseInt(limit)), pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) } });
});

app.get('/api/orders/:id', auth, (req, res) => {
  const order = db.data.orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Sipariş bulunamadı' });
  const history = db.data.order_history.filter(h => h.order_id === order.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ ...order, history });
});

app.put('/api/orders/:id', auth, async (req, res) => {
  const i = db.data.orders.findIndex(o => o.id === parseInt(req.params.id));
  if (i === -1) return res.status(404).json({ error: 'Sipariş bulunamadı' });
  const oldStatus = db.data.orders[i].status;
  db.data.orders[i] = { ...db.data.orders[i], ...req.body, updated_at: new Date().toISOString() };
  if (oldStatus !== req.body.status) {
    db.data.order_history.push({ id: Date.now(), order_id: parseInt(req.params.id), old_status: oldStatus, new_status: req.body.status, changed_by: req.user.id, created_at: new Date().toISOString() });
  }
  await db.write();
  res.json({ message: 'Sipariş güncellendi' });
});

app.patch('/api/orders/:id/status', auth, async (req, res) => {
  const { status, note } = req.body;
  const i = db.data.orders.findIndex(o => o.id === parseInt(req.params.id));
  if (i === -1) return res.status(404).json({ error: 'Sipariş bulunamadı' });
  const oldStatus = db.data.orders[i].status;
  db.data.orders[i].status = status;
  db.data.orders[i].updated_at = new Date().toISOString();
  db.data.order_history.push({ id: Date.now(), order_id: parseInt(req.params.id), old_status: oldStatus, new_status: status, changed_by: req.user.id, note, created_at: new Date().toISOString() });
  await db.write();
  res.json({ message: 'Durum güncellendi' });
});

app.delete('/api/orders/:id', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  db.data.orders = db.data.orders.filter(o => o.id !== id);
  db.data.order_history = db.data.order_history.filter(h => h.order_id !== id);
  await db.write();
  res.json({ message: 'Sipariş silindi' });
});

// PUBLIC ORDER
app.post('/api/public/orders', async (req, res) => {
  const { site_url, customer_name, customer_phone, customer_email, address, city, district, neighborhood, products, total_quantity, total_amount, payment_method, customer_note } = req.body;
  if (!customer_name || !customer_phone || !address) return res.status(400).json({ error: 'Zorunlu alanlar eksik' });
  
  const site = db.data.sites.find(s => s.site_url === site_url || s.site_name === site_url);
  if (!site) return res.status(400).json({ error: 'Site bulunamadı' });
  
  if (db.data.blocklist.find(b => b.type === 'phone' && b.value === customer_phone)) return res.status(403).json({ error: 'Telefon engellenmiş' });
  
  const orderNumber = generateOrderNumber();
  const order = {
    id: generateId('orders'),
    order_number: orderNumber,
    site_id: site.id,
    customer_name, customer_phone, customer_email, address, city, district, neighborhood,
    products: typeof products === 'string' ? products : JSON.stringify(products),
    total_quantity: total_quantity || 1,
    total_amount: parseFloat(total_amount) || 0,
    payment_method: payment_method || 'Kapıda Ödeme',
    status: 'Yeni',
    customer_note,
    ip_address: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  
  db.data.orders.push(order);
  db.data.order_history.push({ id: Date.now(), order_id: order.id, new_status: 'Yeni', note: 'Sipariş oluşturuldu', created_at: new Date().toISOString() });
  await db.write();
  
  res.json({ success: true, order_number: orderNumber, message: 'Siparişiniz başarıyla alındı' });
});

app.get('/api/public/sites/:url', (req, res) => {
  const site = db.data.sites.find(s => s.site_url === req.params.url && s.status === 'active');
  if (!site) return res.status(404).json({ error: 'Site bulunamadı' });
  const products = db.data.products.filter(p => p.site_id === site.id && p.status === 'active');
  res.json({ ...site, products });
});

// OTHER ENDPOINTS
app.get('/api/shipping-companies', auth, (req, res) => res.json(db.data.shipping_companies));
app.get('/api/blocklist', auth, (req, res) => res.json(db.data.blocklist));
app.post('/api/blocklist', auth, async (req, res) => {
  db.data.blocklist.push({ id: Date.now(), ...req.body, created_at: new Date().toISOString() });
  await db.write();
  res.json({ message: 'Engelleme eklendi' });
});
app.delete('/api/blocklist/:id', auth, async (req, res) => {
  db.data.blocklist = db.data.blocklist.filter(b => b.id !== parseInt(req.params.id));
  await db.write();
  res.json({ message: 'Engelleme kaldırıldı' });
});
app.get('/api/message-templates', auth, (req, res) => res.json(db.data.message_templates));
app.get('/api/order-statuses', auth, (req, res) => res.json([
  { value: 'Yeni', label: 'Yeni', color: '#10B981' },
  { value: 'Eksik', label: 'Eksik', color: '#F59E0B' },
  { value: 'Onaylı', label: 'Onaylı', color: '#3B82F6' },
  { value: 'İptal', label: 'İptal', color: '#EF4444' },
  { value: 'Tedarik', label: 'Tedarik', color: '#8B5CF6' },
  { value: 'Kargo', label: 'Kargo', color: '#06B6D4' },
  { value: 'Paket', label: 'Paket', color: '#F97316' },
  { value: 'Teslim', label: 'Teslim', color: '#22C55E' },
  { value: 'İleri Tarihli', label: 'İleri Tarihli', color: '#64748B' },
  { value: 'Çöp', label: 'Çöp', color: '#374151' },
  { value: 'Ulaşılamayan', label: 'Ulaşılamayan', color: '#DC2626' },
  { value: 'İade', label: 'İade', color: '#9333EA' }
]));

// Serve admin panel
app.use(express.static(join(__dirname, '../admin-panel')));
app.get('/', (req, res) => res.sendFile(join(__dirname, '../admin-panel/index.html')));

app.listen(PORT, () => {
  console.log(`🚀 Sipariş Yönetim Sistemi: http://localhost:${PORT}`);
  console.log(`🔑 Giriş: admin / admin123`);
});
