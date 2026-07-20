require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('⚠️ WARNING: No JWT_SECRET in environment. Using fallback for local dev. MUST configure for production!');
}
const secretKey = JWT_SECRET || 'super_secret_capstone_key_2026';

app.use(cors()); // Allow all origins for Capstone flexibility
app.use(express.json());

// ── Authentication Middleware ──────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token expired or invalid.' });
    req.user = user;
    next();
  });
};

const getRoleTable = (role) => {
  if (role === 'admin') return 'ADMINISTRATOR';
  if (role === 'organization') return 'ORGANIZATION';
  return 'DONOR';
};

const getRoleIDColumn = (role) => {
  if (role === 'admin') return 'Admin_ID';
  if (role === 'organization') return 'Org_ID';
  return 'Donor_ID';
}

// ── Routes: Registration ──────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide all required fields.' });
  }

  const validRoles = ['donor', 'organization', 'admin'];
  const assignedRole = validRoles.includes(role) ? role : 'donor';
  const tableName = getRoleTable(assignedRole);
  const idCol = getRoleIDColumn(assignedRole);
  const username = email; // ERD uses Username, frontend passes email

  try {
    const [existingRows] = await db.query(`SELECT * FROM ${tableName} WHERE Username = ?`, [username]);
    if (existingRows.length > 0) return res.status(400).json({ error: 'Username/Email already exists in the system.' });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      `INSERT INTO ${tableName} (Username, Password) VALUES (?, ?)`,
      [username, hash]
    );

    const token = jwt.sign({ id: result.insertId, email: username, role: assignedRole }, secretKey, { expiresIn: '24h' });
    res.status(201).json({
      message: 'Registration successful!',
      token,
      user: { id: result.insertId, name: username, email: username, role: assignedRole }
    });
  } catch (error) {
    res.status(500).json({ error: 'Database insert error: ' + error.message });
  }
});

// ── Routes: Login ─────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Please provide email, password, and select an account type.' });
  }

  try {
    let user = null;
    let foundRole = role;
    let idCol = null;
    let table = null;

    if (role === 'donor') {
      table = 'DONOR'; idCol = 'Donor_ID';
    } else if (role === 'organization') {
      table = 'ORGANIZATION'; idCol = 'Org_ID';
    } else if (role === 'admin') {
      table = 'ADMINISTRATOR'; idCol = 'Admin_ID';
    } else {
      return res.status(400).json({ error: 'Invalid account type selected.' });
    }

    const [rows] = await db.query(`SELECT * FROM ${table} WHERE Username = ?`, [email]);
    if (rows.length > 0) {
      user = rows[0];
    } else {
      return res.status(401).json({ error: `Not registered as an ${role === 'donor' ? 'Individual' : role === 'organization' ? 'Organization' : 'Administrator'}. Please select the correct account type above.` });
    }

    const isMatch = await bcrypt.compare(password, user.Password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: user[idCol], email: user.Username, role: foundRole }, secretKey, { expiresIn: '24h' });
    res.json({
      message: 'Login successful!',
      token,
      user: { id: user[idCol], name: user.Username, email: user.Username, role: foundRole, wallet_address: user.Wallet_Address, verification_status: user.Verification_Status }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error on login: ' + error.message });
  }
});

// ── Routes: Me (Get Profile) ──────────────────────────────
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const tableName = getRoleTable(req.user.role);
  const idCol = getRoleIDColumn(req.user.role);

  try {
    const [rows] = await db.query(`SELECT * FROM ${tableName} WHERE ${idCol} = ?`, [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    const user = rows[0];
    res.json({ user: { id: user[idCol], name: user.Username, email: user.Username, role: req.user.role, wallet_address: user.Wallet_Address, verification_status: user.Verification_Status } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Routes: Update Wallet Address ─────────────────────────
app.post('/api/auth/wallet', authenticateToken, async (req, res) => {
  const { wallet_address } = req.body;
  if (wallet_address === undefined) return res.status(400).json({ error: 'Wallet address required.' });

  const tableName = getRoleTable(req.user.role);
  const idCol = getRoleIDColumn(req.user.role);
  const targetAddress = wallet_address === '' ? null : wallet_address;

  try {
    await db.query(`UPDATE ${tableName} SET Wallet_Address = ? WHERE ${idCol} = ?`, [targetAddress, req.user.id]);
    res.json({ message: 'Wallet address synchronized successfully.', wallet_address: targetAddress });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Web3 Synchronization Routes ─────────────────────────────

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  if (req.user.role !== 'organization') return res.status(403).json({ error: 'Only organizations can save campaigns.' });

  try {
    // Check if Organization is approved
    const [orgRows] = await db.query('SELECT Verification_Status FROM ORGANIZATION WHERE Org_ID = ?', [req.user.id]);
    if (orgRows.length === 0 || orgRows[0].Verification_Status !== 'Approved') {
      return res.status(403).json({ error: 'Your organization must be manually Approved by an Admin before creating campaigns.' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Database verification failed: ' + err.message });
  }

  const { title, target_amount, contract_address } = req.body;
  if (!title || !target_amount) return res.status(400).json({ error: 'Missing campaign data.' });

  try {
    await db.query(
      `INSERT INTO CAMPAIGN (Org_ID, Campaign_Title, Target_Amount, Smart_Contract_Address) VALUES (?, ?, ?, ?)`,
      [req.user.id, title, target_amount, contract_address || null]
    );
    res.status(201).json({ message: 'Campaign verified and saved to database.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync campaign: ' + err.message });
  }
});

app.post('/api/donations', authenticateToken, async (req, res) => {
  if (req.user.role !== 'donor' && req.user.role !== 'organization') return res.status(403).json({ error: 'Only donors or organizations can record transactions.' });

  const { campaign_id, tx_hash, amount, is_anonymous } = req.body;
  if (!campaign_id || !tx_hash || !amount) return res.status(400).json({ error: 'Missing transaction data.' });

  try {
    const anonymousFlag = is_anonymous ? 1 : 0;
    const donorId = req.user.role === 'donor' ? req.user.id : null;
    const orgId = req.user.role === 'organization' ? req.user.id : null;

    await db.query(
      `INSERT IGNORE INTO DONATION_TRANSACTION (Donor_ID, Org_ID, Campaign_ID, Tx_Hash, Amount, Is_Anonymous) VALUES (?, ?, ?, ?, ?, ?)`,
      [donorId, orgId, campaign_id, tx_hash, amount, anonymousFlag]
    );
    res.status(201).json({ message: 'Blockchain transaction recorded successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync donation: ' + err.message });
  }
});

app.get('/api/donations/me', authenticateToken, async (req, res) => {
  if (req.user.role !== 'donor' && req.user.role !== 'organization') return res.status(403).json({ error: 'Invalid role.' });
  try {
    const [rows] = await db.query(`
      SELECT dt.Campaign_ID as campaignId, dt.Amount as amount, dt.Tx_Hash as txHash, dt.Is_Anonymous as isAnonymous
      FROM DONATION_TRANSACTION dt
      WHERE ${req.user.role === 'donor' ? 'dt.Donor_ID = ?' : 'dt.Org_ID = ?'}
    `, [req.user.id]);
    res.json(rows.reverse());
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch personal donations: ' + err.message });
  }
});

app.get('/api/campaigns', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        c.Campaign_ID as id, 
        c.Campaign_Title as title, 
        c.Target_Amount as targetAmount,
        o.Wallet_Address as orgAddress,
        c.Smart_Contract_Address as contractAddress,
        COALESCE(SUM(dt.Amount), 0) as currentAmount
      FROM CAMPAIGN c
      LEFT JOIN DONATION_TRANSACTION dt ON c.Campaign_ID = dt.Campaign_ID
      LEFT JOIN ORGANIZATION o ON c.Org_ID = o.Org_ID
      GROUP BY c.Campaign_ID
    `);

    const formatted = rows.map(r => ({
      id: r.id,
      title: r.title,
      targetAmount: r.targetAmount.toString(),
      currentAmount: r.currentAmount.toString(),
      orgAddress: r.orgAddress || 'Unknown Org',
      isActive: true, // Offline mode default (Web3 fixes this if online)
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public API ────────────────────────────────────────────
app.get('/api/public-stats', async (req, res) => {
  try {
    const [donors] = await db.query('SELECT COUNT(*) as c FROM DONOR');
    const [orgs] = await db.query("SELECT COUNT(*) as c FROM ORGANIZATION WHERE Verification_Status = 'Approved'");
    const [campaigns] = await db.query('SELECT COUNT(*) as c FROM CAMPAIGN');
    res.json({
      donors: donors[0].c,
      orgs: orgs[0].c,
      campaigns: campaigns[0].c
    });
  } catch (err) {
    res.json({ donors: 0, orgs: 0, campaigns: 0 });
  }
});

app.get('/api/campaigns/:id/donations', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT dt.Tx_Hash, dt.Amount, dt.Is_Anonymous, 
             COALESCE(d.Wallet_Address, o.Wallet_Address) as wallet, 
             COALESCE(d.Username, o.Username) as donorName
      FROM DONATION_TRANSACTION dt
      LEFT JOIN DONOR d ON dt.Donor_ID = d.Donor_ID
      LEFT JOIN ORGANIZATION o ON dt.Org_ID = o.Org_ID
      WHERE dt.Campaign_ID = ?
    `, [req.params.id]);
    res.json(rows.reverse()); // Reverse to show latest first based on insertion
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch donations: ' + err.message });
  }
});

// ── Routes: Admin (Organization Approval) ─────────────────
app.get('/api/admin/organizations', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
  try {
    const [rows] = await db.query(`SELECT Org_ID, Username, Verification_Status, Wallet_Address FROM ORGANIZATION`);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/organizations/:id/approve', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
  try {
    await db.query(`UPDATE ORGANIZATION SET Verification_Status = 'Approved' WHERE Org_ID = ?`, [req.params.id]);
    res.json({ message: 'Organization approved successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 BBDRTS API Server running on http://localhost:${PORT}`);
});
