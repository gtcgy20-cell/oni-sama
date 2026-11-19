const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto');
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'50kb'}));
app.use((q,r,n)=>{r.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Strict-Transport-Security':'max-age=31536000'});n()});
let SECRET=process.env.JWT_SECRET;if(!SECRET){SECRET=crypto.randomBytes(32).toString('hex');console.warn('WARNING: set JWT_SECRET env var, otherwise logins reset on every restart')}
const db=new Database(process.env.DB_PATH||'oni.db');db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,email TEXT UNIQUE,phone TEXT,role TEXT DEFAULT 'customer',hash TEXT);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY,name TEXT,cat TEXT,price REAL,color TEXT,stock INTEGER);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,uid INTEGER,name TEXT,phone TEXT,addr TEXT,items TEXT,total REAL,status TEXT,date TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);`);
const CATS=['Hoodies','Jackets','T-Shirts','Cotton Pants','Joggers'],SZ=['S','M','L','XL'],ST=['Placed','Confirmed','Packed','Shipped','Delivered','Cancelled'];
/* seed */
if(!db.prepare('SELECT 1 FROM products').get()){const ins=db.prepare('INSERT INTO products VALUES(?,?,?,?,?,25)');[['Void Oversized Hoodie','Hoodies',89,'#111111'],['Voltage Zip Hoodie','Hoodies',99,'#1e6bff'],['Shadow Bomber Jacket','Jackets',189,'#1a1a1a'],['Arc Tech Jacket','Jackets',219,'#2a3550'],['Ivory Essential Tee','T-Shirts',39,'#f2f2f2'],['Noir Graphic Tee','T-Shirts',45,'#0a0a0a'],['Cobalt Boxy Tee','T-Shirts',42,'#1e6bff'],['Tailored Cotton Pants','Cotton Pants',95,'#d8d4cc'],['Onyx Cargo Pants','Cotton Pants',105,'#161616'],['Pulse Joggers','Joggers',79,'#1b1b1b'],['Electric Stripe Joggers','Joggers',85,'#243b7a']].forEach((p,i)=>ins.run('p'+i,...p))}
db.prepare("INSERT OR IGNORE INTO settings VALUES('wa','918110079002')").run();
if(!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(9).toString('base64url');
db.prepare("INSERT INTO users(name,email,phone,role,hash) VALUES('ONI Admin',?,'','admin',?)").run((process.env.ADMIN_EMAIL||'admin@onisama.com').toLowerCase(),bcrypt.hashSync(pw,12));
console.log('Admin created: '+(process.env.ADMIN_EMAIL||'admin@onisama.com')+(process.env.ADMIN_PASSWORD?'':' / password: '+pw+'  (save it now)'))}
/* helpers */
const now=()=>new Date().toISOString().slice(0,16).replace('T',' ');
const fmt=o=>({...o,items:typeof o.items==='string'?JSON.parse(o.items):o.items});
const tok=u=>jwt.sign({id:u.id,role:u.role,name:u.name},SECRET,{expiresIn:'7d'});
const pub=u=>({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role});
const auth=(q,r,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').slice(7),SECRET);n()}catch(e){r.status(401).json({error:'Please log in'})}};
const adm=(q,r,n)=>q.u.role==='admin'?n():r.status(403).json({error:'Admin only'});
const hits=new Map();const lim=(q,r,n)=>{const t=Date.now(),a=(hits.get(q.ip)||[]).filter(x=>t-x<9e5);if(a.length>=20)return r.status(429).json({error:'Too many attempts, try again later'});a.push(t);hits.set(q.ip,a);n()};
const pv=b=>{const n=String(b.name||'').trim().slice(0,80),p=+b.price,s=Math.floor(+b.stock);return n&&CATS.includes(b.cat)&&p>=0&&p<1e6&&s>=0&&/^#[0-9a-f]{6}$/i.test(b.color)?[n,b.cat,p,b.color,s]:null};
/* public */
app.get('/api/shop',(q,r)=>r.json({products:db.prepare('SELECT * FROM products').all(),wa:db.prepare("SELECT v FROM settings WHERE k='wa'").get().v}));
app.get('/api/track',(q,r)=>{const o=db.prepare('SELECT * FROM orders WHERE id=? AND phone=?').get(String(q.query.id||'').toUpperCase(),String(q.query.phone||''));o?r.json(fmt(o)):r.status(404).json({error:'Not found'})});
/* auth */
app.post('/api/register',lim,(q,r)=>{const b=q.body,n=String(b.name||'').trim().slice(0,80),e=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
if(!n||!/^\S+@\S+\.\S+$/.test(e)||pw.length<8||pw.length>72)return r.status(400).json({error:'Enter name, valid email and 8+ char password'});
if(db.prepare('SELECT 1 FROM users WHERE email=?').get(e))return r.status(400).json({error:'Email already registered'});
const id=db.prepare("INSERT INTO users(name,email,phone,role,hash) VALUES(?,?,?, 'customer',?)").run(n,e,String(b.phone||'').slice(0,20),bcrypt.hashSync(pw,12)).lastInsertRowid;
const u=db.prepare('SELECT * FROM users WHERE id=?').get(id);r.json({token:tok(u),user:pub(u)})});
app.post('/api/login',lim,(q,r)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(q.body.email||'').trim().toLowerCase());
if(!u||!bcrypt.compareSync(String(q.body.password||''),u.hash))return r.status(401).json({error:'Invalid email or password'});r.json({token:tok(u),user:pub(u)})});
app.get('/api/me',auth,(q,r)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(q.u.id);u?r.json({user:pub(u)}):r.status(401).json({error:'Please log in'})});
/* orders */
app.post('/api/orders',auth,(q,r)=>{const b=q.body,n=String(b.name||'').trim().slice(0,100),ph=String(b.phone||'').trim().slice(0,20),ad=String(b.addr||'').trim().slice(0,300);
if(!n||!ph||!ad||!Array.isArray(b.items)||!b.items.length||b.items.length>30)return r.status(400).json({error:'Invalid order'});
try{const o=db.transaction(()=>{let t=0;const it=b.items.map(i=>{const p=db.prepare('SELECT * FROM products WHERE id=?').get(String(i.id)),y=Math.floor(+i.qty);
if(!p||!SZ.includes(i.size)||!(y>=1&&y<=10))throw new Error('Invalid item');if(p.stock<y)throw new Error(p.name+' is out of stock');
db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(y,p.id);t+=p.price*y;return{id:p.id,name:p.name,size:i.size,qty:y,price:p.price}});
const o={id:'ONI-'+crypto.randomBytes(4).toString('hex').toUpperCase(),uid:q.u.id,name:n,phone:ph,addr:ad,items:JSON.stringify(it),total:t,status:'Placed',date:now()};
db.prepare('INSERT INTO orders VALUES(@id,@uid,@name,@phone,@addr,@items,@total,@status,@date)').run(o);return o})();r.json(fmt(o))}catch(e){r.status(400).json({error:e.message})}});
app.get('/api/orders',auth,(q,r)=>{const rows=q.u.role==='admin'?db.prepare('SELECT * FROM orders ORDER BY rowid DESC').all():db.prepare('SELECT * FROM orders WHERE uid=? ORDER BY rowid DESC').all(q.u.id);r.json(rows.map(fmt))});
app.patch('/api/orders/:id',auth,adm,(q,r)=>{const s=q.body.status,o=db.prepare('SELECT * FROM orders WHERE id=?').get(q.params.id);if(!o||!ST.includes(s))return r.status(400).json({error:'Invalid'});
db.transaction(()=>{if(s==='Cancelled'&&o.status!=='Cancelled')JSON.parse(o.items).forEach(i=>db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty,i.id));db.prepare('UPDATE orders SET status=? WHERE id=?').run(s,o.id)})();r.json({ok:1})});
/* admin */
app.post('/api/products',auth,adm,(q,r)=>{const v=pv(q.body);if(!v)return r.status(400).json({error:'Invalid product'});db.prepare('INSERT INTO products VALUES(?,?,?,?,?,?)').run('p'+Date.now().toString(36),...v);r.json({ok:1})});
app.put('/api/products/:id',auth,adm,(q,r)=>{const v=pv(q.body);if(!v)return r.status(400).json({error:'Invalid product'});db.prepare('UPDATE products SET name=?,cat=?,price=?,color=?,stock=? WHERE id=?').run(...v,q.params.id);r.json({ok:1})});
app.delete('/api/products/:id',auth,adm,(q,r)=>{db.prepare('DELETE FROM products WHERE id=?').run(q.params.id);r.json({ok:1})});
app.put('/api/wa',auth,adm,(q,r)=>{const w=String(q.body.wa||'').replace(/\D/g,'').slice(0,15);if(w.length<8)return r.status(400).json({error:'Invalid number'});db.prepare("UPDATE settings SET v=? WHERE k='wa'").run(w);r.json({wa:w})});
app.delete('/api/me',auth,lim,(q,r)=>{const u=db.prepare('SELECT * FROM users WHERE id=?').get(q.u.id);if(!u)return r.status(401).json({error:'Please log in'});if(u.role==='admin')return r.status(400).json({error:'Admin account cannot be deleted here'});
if(!bcrypt.compareSync(String(q.body.password||''),u.hash))return r.status(401).json({error:'Wrong password'});
db.transaction(()=>{db.prepare("UPDATE orders SET uid=NULL,name='Deleted user',phone='',addr='' WHERE uid=?").run(u.id);db.prepare('DELETE FROM users WHERE id=?').run(u.id)})();r.json({ok:1})});
app.use('/api',(q,r)=>r.status(404).json({error:'Not found'}));
app.use('/.well-known',express.static(path.join(__dirname,'public/.well-known'),{dotfiles:'allow'}));
app.use(express.static(path.join(__dirname,'public')));
app.listen(process.env.PORT||3000,()=>console.log('ONI SAMA running'));
