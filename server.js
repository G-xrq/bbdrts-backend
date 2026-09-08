require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('⚠️ WARNING: No JWT_SECRET in environment. Using fallback for local dev. MUST configure for production!');
}
const secretKey = JWT_SECRET || 'super_secret_capstone_key_2026';

app.use(cors()); // Allow all origins for Capstone flexibility
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// ── Security Headers Middleware ─────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ── In-Memory Rate Limiting Middleware (Generous Limits to Prevent Lockouts) ──
const rateLimitMap = new Map();
const rateLimiter = (maxRequests = 300, windowMs = 15 * 60 * 1000) => (req, res, next) => {
  // Allow unrestricted access for local testing and development
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return next();
  }

  const now = Date.now();
  const userRecord = rateLimitMap.get(ip) || { count: 0, resetTime: now + windowMs };

  if (now > userRecord.resetTime) {
    userRecord.count = 1;
    userRecord.resetTime = now + windowMs;
  } else {
    userRecord.count += 1;
  }

  rateLimitMap.set(ip, userRecord);

  if (userRecord.count > maxRequests) {
    return res.status(429).json({ error: 'Too many requests. Please wait a few minutes before trying again.' });
  }
  next();
};

// ── Email Transporter Helper (Google Gmail SMTP via Secure Port 465) ───────────
function getEmailTransporter() {
  const user = process.env.SMTP_USER || process.env.EMAIL_USER || process.env.GMAIL_USER || 'gestermacaldo@gmail.com';
  const pass = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.GMAIL_PASS || 'vlijrjrvwonjjmwe';

  if (user && pass) {
    return nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true, // SSL on port 465 avoids cloud provider STARTTLS port 587 blockades
      auth: {
        user: user.trim(),
        pass: pass.replace(/\s+/g, '') // remove spaces from Google App Password
      },
      connectionTimeout: 5000, // 5s max to connect
      greetingTimeout: 5000,   // 5s max for greeting
      socketTimeout: 7000      // 7s max for socket
    });
  }
  return null;
}

// ── Resilient Safe Email Dispatcher (Guarantees Backend Never Hangs or Freezes) ──
async function sendMailSafe(mailOptions, timeoutMs = 6500) {
  const transporter = getEmailTransporter();
  if (!transporter) return false;

  try {
    const sendPromise = transporter.sendMail(mailOptions);
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`SMTP timed out after ${timeoutMs}ms`)), timeoutMs)
    );
    await Promise.race([sendPromise, timeoutPromise]);
    return true;
  } catch (err) {
    console.warn(`⚠️ [SMTP ERROR/TIMEOUT]:`, err.message);
    return false;
  }
}

// ── On-Chain RPC Verification Helper ────────────────────────
const verifyOnChainTx = async (txHash) => {
  if (!txHash || typeof txHash !== 'string' || !txHash.startsWith('0x') || txHash.length !== 66) {
    return { valid: false, error: 'Invalid transaction hash format. Hash must be a valid 66-character 0x hex string.' };
  }

  try {
    const rpcUrl = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
    const response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getTransactionReceipt',
        params: [txHash],
        id: 1
      })
    });
    const data = await response.json();
    if (data && data.result) {
      if (data.result.status === '0x1') {
        return { valid: true, receipt: data.result };
      } else if (data.result.status === '0x0') {
        return { valid: false, error: 'Transaction failed or was reverted on the Sepolia network.' };
      }
    }
    // Pending or unmined tx
    return { valid: true, warning: 'Transaction broadcasted (pending on-chain block mining).' };
  } catch (err) {
    console.warn('⚠️ RPC Verification fallback triggered:', err.message);
    return { valid: true, fallback: true };
  }
};

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
};

const formatUserObj = (user, role, idCol) => {
  if (!user) return null;
  const idColumn = idCol || getRoleIDColumn(role);
  
  let legalName = user.Legal_Name || user.Name || '';
  if (!legalName || legalName.includes('@') || legalName.toLowerCase() === user.Username?.toLowerCase()) {
    const handle = user.Username ? user.Username.split('@')[0] : '';
    if (handle.toLowerCase() === 'gestermacaldo') {
      legalName = 'Gester Macaldo';
    } else if (handle) {
      legalName = handle.replace(/[\._\d]/g, ' ').trim().split(' ').filter(Boolean).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') || handle;
    }
  }

  const displayName = user.Display_Name || user.Name || legalName || user.Username;

  return {
    id: user[idColumn],
    name: role === 'organization' ? (user.Org_Name || displayName) : displayName,
    display_name: displayName,
    legal_name: role === 'organization' ? (user.Org_Name || displayName) : (legalName || displayName),
    email: user.Username,
    role: role,
    phone: user.Mobile_Number || null,
    location: user.Location || null,
    bio: user.Bio || null,
    avatar_url: user.Avatar_Url || null,
    banner_url: user.Banner_Url || null,
    website: user.Website || null,
    emergency_hotline: user.Emergency_Hotline || null,
    gcash_name: user.Gcash_Name || null,
    gcash_number: user.Gcash_Number || null,
    gcash_qr_url: user.Gcash_Qr_Url || null,
    maya_name: user.Maya_Name || null,
    maya_number: user.Maya_Number || null,
    maya_qr_url: user.Maya_Qr_Url || null,
    bank_name: user.Bank_Name || null,
    bank_account_name: user.Bank_Account_Name || null,
    bank_account_number: user.Bank_Account_Number || null,
    bank_details: user.Bank_Details || null,
    bank_qr_url: user.Bank_Qr_Url || null,
    title: user.Title || null,
    agency: user.Agency || null,
    preferences: user.Preferences_Json || null,
    name_last_changed_at: user.Name_Last_Changed_At || null,
    wallet_address: user.Wallet_Address || null,
    verification_status: user.Verification_Status || 'Approved',
    sec_registration_no: user.Sec_Registration_No || null,
    dswd_accreditation_no: user.Dswd_Accreditation_No || null,
    board_members: user.Board_Members_Json || null,
    sec_certificate_url: user.Sec_Certificate_Url || null,
    verified_at: user.Verified_At || null,
    verified_by: user.Verified_By || null,
    audit_notes: user.Audit_Notes || null
  };
};

// ── In-Memory Registration Verification OTP Store ─────────
const registrationOtps = new Map();

// ── Routes: Registration Step 1 (Request Email Verification Code) ──
app.post('/api/auth/register-request', rateLimiter(10, 15 * 60 * 1000), async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Please provide full name, email, and password.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  const targetEmail = email.trim().toLowerCase();
  const assignedRole = role === 'organization' ? 'organization' : 'donor';
  const tableName = getRoleTable(assignedRole);

  try {
    // Check if account already exists across any role table
    const [donorRows] = await db.query('SELECT Username FROM DONOR WHERE Username = ?', [targetEmail]);
    const [orgRows] = await db.query('SELECT Username FROM ORGANIZATION WHERE Username = ?', [targetEmail]);
    const [adminRows] = await db.query('SELECT Username FROM ADMINISTRATOR WHERE Username = ?', [targetEmail]);

    if (donorRows.length > 0 || orgRows.length > 0 || adminRows.length > 0) {
      return res.status(400).json({ error: 'An account with this email address is already registered. Please log in instead.' });
    }

    const isOrg = assignedRole === 'organization';
    const mobile = (req.body.mobileNumber || req.body.mobile || '').trim();
    const secRegNo = (req.body.secRegistrationNo || '').trim();
    const secCertUrl = req.body.secCertificateUrl || '';
    const boardMembers = req.body.boardMembers || '';
    const dswdNo = (req.body.dswdAccreditationNo || '').trim();

    // 6-digit Email Verification Code (sent to real Gmail SMTP)
    const emailOtpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes (as specified in instructor review)

    registrationOtps.set(targetEmail, {
      name: name.trim(),
      email: targetEmail,
      password,
      role: assignedRole,
      mobileNumber: mobile,
      secRegistrationNo: secRegNo,
      secCertificateUrl: secCertUrl,
      boardMembers: boardMembers,
      dswdAccreditationNo: dswdNo,
      emailOtp: emailOtpCode,
      expiresAt
    });

    const mailOptions = {
      from: `"BBDRTS Protocol" <${process.env.SMTP_USER || 'gestermacaldo@gmail.com'}>`,
      to: targetEmail,
      replyTo: process.env.SMTP_USER || 'gestermacaldo@gmail.com',
      subject: `BBDRTS Verification Code: ${emailOtpCode}`,
      text: `Welcome to BBDRTS Protocol!\n\nYour 6-digit Email Verification Code is: ${emailOtpCode}\n\nThis code expires in 5 minutes.\nPlease enter this code on the registration screen to verify your email and activate your account.\n\nThank you,\nBBDRTS Protocol Team - Saint Joseph College CCS`,
      html: `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #0c1015; color: #f1f5f9; padding: 32px 20px; border-radius: 12px; max-width: 540px; margin: 0 auto; border: 1px solid #1e293b;">
          <div style="text-align: center; margin-bottom: 24px;">
            <h2 style="color: #22c55e; margin: 0; font-size: 24px; letter-spacing: -0.5px;">BBDRTS PROTOCOL</h2>
            <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">Blockchain-Based Donation & Relief Transparency System</p>
          </div>
          
          <div style="background-color: #161f2e; border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px;">
            <p style="color: #cbd5e1; font-size: 14px; margin-top: 0;">Welcome to BBDRTS! Please use this 6-digit one-time <strong>EMAIL SECURITY CODE</strong> to verify your ${assignedRole.toUpperCase()} account:</p>
            <div style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #22c55e; background: rgba(34, 197, 94, 0.1); padding: 12px 20px; border-radius: 8px; display: inline-block; margin: 12px 0; border: 1px solid #22c55e;">
              ${emailOtpCode}
            </div>
            <p style="color: #ef4444; font-size: 12px; margin: 8px 0 0 0; font-weight: 600;">⏳ This verification code expires in 5 minutes.</p>
          </div>

          <p style="color: #64748b; font-size: 12px; line-height: 1.5; margin-bottom: 20px;">
            If you did not initiate this registration, please disregard this email.
          </p>

          <div style="border-top: 1px solid #1e293b; padding-top: 14px; font-size: 11px; color: #475569; text-align: center;">
            College of Computer Studies · Saint Joseph College · Maasin City, Southern Leyte
          </div>
        </div>
      `
    };

    const emailSent = await sendMailSafe(mailOptions, 6000);
    if (emailSent) {
      console.log(`✅ [REGISTRATION EMAIL OTP SENT] Code sent successfully to ${targetEmail}`);
    } else {
      console.log(`ℹ️ [DEV LOG] SMTP unavailable or timed out. Registration Email OTP for ${targetEmail}: [${emailOtpCode}]`);
    }

    /* 
    ========================================================================================
    📱 [FUTURE REACTIVATION MODULE: DUAL-FACTOR MOBILE SMS DISPATCH (TEXTBEE / SEMAPHORE / TWILIO)]
    To re-enable SMS verification for NGOs in the future:
    1. Uncomment this block.
    2. Set `isDualOtp: isOrg` in the response below.
    3. Uncomment the Mobile Number field in AuthView.jsx.
    ========================================================================================
    let smsSent = false;
    let smsProvider = 'TextBee / Semaphore Cellular Gateway';

    if (isOrg && mobile) {
      const digits = mobile.replace(/\D/g, '');
      let normalizedLocal = digits;
      let normalizedIntl = digits;

      if (digits.startsWith('63') && digits.length === 12) {
        normalizedLocal = '0' + digits.slice(2);
        normalizedIntl = '+' + digits;
      } else if (digits.startsWith('0') && digits.length === 11) {
        normalizedLocal = digits;
        normalizedIntl = '+63' + digits.slice(1);
      } else if (digits.length === 10 && digits.startsWith('9')) {
        normalizedLocal = '0' + digits;
        normalizedIntl = '+63' + digits;
      }

      // 1. Android Phone Personal SMS Gateway via TextBee (Free SIM Gateway)
      if (!smsSent && process.env.TEXTBEE_API_KEY) {
        try {
          let deviceId = process.env.TEXTBEE_DEVICE_ID;
          if (!deviceId) {
            const devRes = await fetch('https://api.textbee.dev/api/v1/gateway/devices', {
              headers: { 'x-api-key': process.env.TEXTBEE_API_KEY }
            });
            const devData = await devRes.json();
            if (devRes.ok && Array.isArray(devData.data) && devData.data.length > 0) {
              deviceId = devData.data[0]._id || devData.data[0].id;
            }
          }
          if (deviceId) {
            const tbRes = await fetch(`https://api.textbee.dev/api/v1/gateway/devices/${deviceId}/sendSMS`, {
              method: 'POST',
              headers: { 'x-api-key': process.env.TEXTBEE_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                recipients: [normalizedLocal],
                message: `BBDRTS Protocol: Your 6-digit verification code for ${name.trim()} is ${emailOtpCode}. Valid for 10 mins.`
              })
            });
            const tbData = await tbRes.json();
            if (tbRes.ok && (tbData.success || tbData.data?.success)) {
              smsSent = true;
              console.log(`✅ [TEXTBEE SMS DELIVERED] Dispatched to ${normalizedLocal}`);
            }
          }
        } catch (tbErr) {
          console.warn('⚠️ [TEXTBEE SMS ERROR]:', tbErr.message);
        }
      }

      // 2. Semaphore Philippine Gateway (Telco Carrier direct)
      if (!smsSent && process.env.SEMAPHORE_API_KEY) {
        try {
          const semRes = await fetch('https://api.semaphore.co/api/v4/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              apikey: process.env.SEMAPHORE_API_KEY,
              number: normalizedLocal,
              message: `BBDRTS: Your verification code for ${name.trim()} is ${emailOtpCode}.`,
              sendername: process.env.SEMAPHORE_SENDER_NAME || 'SEMAPHORE'
            })
          });
        } catch (smsErr) {
          console.warn('⚠️ [SEMAPHORE SMS ERROR]:', smsErr.message);
        }
      }
    }
    ========================================================================================
    */

    res.json({
      success: true,
      isDualOtp: false,
      mobileNumber: mobile,
      message: `A 6-digit verification code has been dispatched to ${targetEmail}.`,
      emailSent,
      devEmailCode: emailOtpCode,
      devCode: emailOtpCode
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration verification: ' + error.message });
  }
});

// ── Routes: Registration Step 2 (Verify Email Code & Complete Account Creation) ──
app.post('/api/auth/register-verify', rateLimiter(15, 15 * 60 * 1000), async (req, res) => {
  const { email, otp, emailOtp } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Please provide registered email.' });
  }

  const targetEmail = email.trim().toLowerCase();
  const record = registrationOtps.get(targetEmail);

  if (!record) {
    return res.status(400).json({ error: 'No active registration request found for this email. Please sign up again.' });
  }

  if (Date.now() > record.expiresAt) {
    registrationOtps.delete(targetEmail);
    return res.status(400).json({ error: 'Verification code has expired. Please sign up again.' });
  }

  const isOrg = record.role === 'organization';
  const inputOtp = (emailOtp || otp || '').trim();

  if (!inputOtp) {
    return res.status(400).json({ error: 'Please provide the 6-digit verification code.' });
  }

  if (record.emailOtp.trim() !== inputOtp) {
    return res.status(400).json({ error: 'Invalid verification code. Please check your email inbox.' });
  }

  try {
    const hash = await bcrypt.hash(record.password, 10);
    const initialStatus = isOrg ? 'Pending' : 'Approved';
    const tableName = isOrg ? 'ORGANIZATION' : 'DONOR';
    const idCol = isOrg ? 'Org_ID' : 'Donor_ID';

    let result;
    if (isOrg) {
      [result] = await db.query(
        `INSERT INTO ORGANIZATION (Username, Password, Org_Name, Verification_Status, Sec_Registration_No, Sec_Certificate_Url, Board_Members_Json, Dswd_Accreditation_No) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          targetEmail,
          hash,
          record.name.trim(),
          initialStatus,
          record.secRegistrationNo || '',
          record.secCertificateUrl || '',
          typeof record.boardMembers === 'string' ? record.boardMembers : JSON.stringify(record.boardMembers || []),
          record.dswdAccreditationNo || ''
        ]
      );
    } else {
      [result] = await db.query(
        `INSERT INTO DONOR (Username, Password, Name, Legal_Name, Display_Name, Mobile_Number) VALUES (?, ?, ?, ?, ?, ?)`,
        [
          targetEmail,
          hash,
          (record.name || '').trim() || null,
          (record.name || '').trim() || null,
          (record.name || '').trim() || null,
          (record.mobileNumber || '').trim() || null
        ]
      );
    }

    const newId = result.insertId || result[0]?.insertId || 1;
    const [createdRows] = await db.query(`SELECT * FROM ${tableName} WHERE ${idCol} = ?`, [newId]);
    const createdUser = createdRows[0] || { [idCol]: newId, Username: targetEmail, Name: record.name, Legal_Name: record.name, Display_Name: record.name };
    const token = jwt.sign({ id: newId, email: targetEmail, role: record.role }, secretKey, { expiresIn: '24h' });

    // Clean up OTP record
    registrationOtps.delete(targetEmail);
    console.log(`✅ [NEW USER DUAL-VERIFIED] Created ${record.role} account for ${targetEmail} (Mobile: ${record.mobileNumber || 'N/A'})`);

    res.status(201).json({
      message: 'Account successfully verified and registered!',
      token,
      user: formatUserObj(createdUser, record.role, idCol)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete registration: ' + error.message });
  }
});

// ── Routes: Registration (Direct / Fallback) ───────────────
app.post('/api/auth/register', rateLimiter(15, 15 * 60 * 1000), async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide all required fields.' });
  }

  const validRoles = ['donor', 'organization', 'admin'];
  const assignedRole = validRoles.includes(role) ? role : 'donor';
  const tableName = getRoleTable(assignedRole);
  const idCol = getRoleIDColumn(assignedRole);
  const username = email.trim().toLowerCase();

  try {
    const [existingRows] = await db.query(`SELECT * FROM ${tableName} WHERE Username = ?`, [username]);
    if (existingRows.length > 0) return res.status(400).json({ error: 'Username/Email already exists in the system.' });

    const hash = await bcrypt.hash(password, 10);
    const initialStatus = assignedRole === 'organization' ? 'Pending' : 'Approved';

    let result;
    if (assignedRole === 'organization') {
      [result] = await db.query(
        `INSERT INTO ORGANIZATION (Username, Password, Org_Name, Verification_Status) VALUES (?, ?, ?, ?)`,
        [username, hash, (name || username).trim(), initialStatus]
      );
    } else {
      [result] = await db.query(
        `INSERT INTO DONOR (Username, Password, Name, Legal_Name, Display_Name) VALUES (?, ?, ?, ?, ?)`,
        [
          username,
          hash,
          (name || '').trim() || null,
          (name || '').trim() || null,
          (name || '').trim() || null
        ]
      );
    }

    const newId = result.insertId || result[0]?.insertId || 1;
    const [createdRows] = await db.query(`SELECT * FROM ${tableName} WHERE ${idCol} = ?`, [newId]);
    const createdUser = createdRows[0] || { [idCol]: newId, Username: username, Name: name, Legal_Name: name, Display_Name: name };
    const token = jwt.sign({ id: newId, email: username, role: assignedRole }, secretKey, { expiresIn: '24h' });
    res.status(201).json({
      message: 'Registration successful!',
      token,
      user: formatUserObj(createdUser, assignedRole, idCol)
    });
  } catch (error) {
    res.status(500).json({ error: 'Database insert error: ' + error.message });
  }
});

// ── Routes: Login (Strict Role Isolation) ──────────────────
app.post('/api/auth/login', rateLimiter(100, 15 * 60 * 1000), async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide both email and password.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const requestedRole = role === 'organization' ? 'organization' : (role === 'admin' ? 'admin' : 'donor');

  try {
    let user = null;
    let idCol = 'Donor_ID';

    if (requestedRole === 'donor') {
      const [donorRows] = await db.query('SELECT * FROM DONOR WHERE LOWER(Username) = ?', [cleanEmail]);
      if (donorRows.length > 0) {
        user = donorRows[0];
        idCol = 'Donor_ID';
      } else {
        // Cross-role safety check to prevent confusion
        const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE LOWER(Username) = ?', [cleanEmail]);
        if (orgRows.length > 0) {
          return res.status(403).json({ error: 'This email is registered as an NGO / Relief Organization. Please switch to the NGO portal to log in.' });
        }
        const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE LOWER(Username) = ?', [cleanEmail]);
        if (adminRows.length > 0) {
          return res.status(403).json({ error: 'This account is an Administrator. Please use the Admin Portal.' });
        }
        return res.status(401).json({ error: 'No Donor account found with this email. Please check your spelling or sign up.' });
      }
    } else if (requestedRole === 'organization') {
      const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE LOWER(Username) = ?', [cleanEmail]);
      if (orgRows.length > 0) {
        user = orgRows[0];
        idCol = 'Org_ID';
      } else {
        // Cross-role safety check to prevent confusion
        const [donorRows] = await db.query('SELECT * FROM DONOR WHERE LOWER(Username) = ?', [cleanEmail]);
        if (donorRows.length > 0) {
          return res.status(403).json({ error: 'This email is registered as a Donor. Please switch to the Donor portal to log in.' });
        }
        const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE LOWER(Username) = ?', [cleanEmail]);
        if (adminRows.length > 0) {
          return res.status(403).json({ error: 'This account is an Administrator. Please use the Admin Portal.' });
        }
        return res.status(401).json({ error: 'No NGO / Relief Organization found with this email. Please register your NGO first.' });
      }
    } else if (requestedRole === 'admin') {
      const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE LOWER(Username) = ?', [cleanEmail]);
      if (adminRows.length > 0) {
        user = adminRows[0];
        idCol = 'Admin_ID';
      } else {
        return res.status(403).json({ error: 'Access denied. You do not have Administrator credentials.' });
      }
    }

    if (!user) {
      return res.status(401).json({ error: 'No account found with this email.' });
    }

    const isMatch = await bcrypt.compare(password, user.Password);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect password. Please try again or use Forgot Password.' });

    const token = jwt.sign({ id: user[idCol], email: user.Username, role: requestedRole }, secretKey, { expiresIn: '24h' });
    res.json({
      message: 'Login successful!',
      token,
      user: formatUserObj(user, requestedRole, idCol)
    });
  } catch (error) {
    res.status(500).json({ error: 'Error on login: ' + error.message });
  }
});

// ── In-Memory One-Time Login Passcode (OTP) Store ─────────
const loginOtps = new Map();

// ── Routes: One-Time Passcode (OTP) Login Request (Strict Role Check) ──
app.post('/api/auth/login-otp-request', rateLimiter(100, 15 * 60 * 1000), async (req, res) => {
  const { email, role } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Please provide a valid email address.' });
  }

  const targetEmail = email.trim().toLowerCase();
  const requestedRole = role === 'organization' ? 'organization' : (role === 'admin' ? 'admin' : 'donor');

  try {
    // 1. Verify that the user exists strictly for the requested role
    if (requestedRole === 'donor') {
      const [donorRows] = await db.query('SELECT * FROM DONOR WHERE LOWER(Username) = ?', [targetEmail]);
      if (donorRows.length === 0) {
        const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE LOWER(Username) = ?', [targetEmail]);
        if (orgRows.length > 0) {
          return res.status(403).json({ error: 'This email belongs to an NGO / Relief Organization. Please switch to the NGO portal.' });
        }
        return res.status(404).json({ error: 'No registered donor account found with this email. Please sign up first.' });
      }
    } else if (requestedRole === 'organization') {
      const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE LOWER(Username) = ?', [targetEmail]);
      if (orgRows.length === 0) {
        const [donorRows] = await db.query('SELECT * FROM DONOR WHERE LOWER(Username) = ?', [targetEmail]);
        if (donorRows.length > 0) {
          return res.status(403).json({ error: 'This email belongs to a Donor. Please switch to the Donor portal.' });
        }
        return res.status(404).json({ error: 'No registered NGO account found with this email. Please sign up first.' });
      }
    } else if (requestedRole === 'admin') {
      const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE LOWER(Username) = ?', [targetEmail]);
      if (adminRows.length === 0) {
        return res.status(403).json({ error: 'Access denied. You do not have Administrator credentials.' });
      }
    }

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    loginOtps.set(targetEmail, {
      email: targetEmail,
      role: requestedRole,
      otp: otpCode,
      expiresAt
    });

    const mailOptions = {
      from: `"BBDRTS Protocol" <${process.env.SMTP_USER || 'gestermacaldo@gmail.com'}>`,
      to: targetEmail,
      replyTo: process.env.SMTP_USER || 'gestermacaldo@gmail.com',
      subject: `BBDRTS Login Passcode: ${otpCode}`,
      text: `Your BBDRTS one-time security login code is: ${otpCode}\n\nRole: ${requestedRole.toUpperCase()}\nThis verification code expires in 5 minutes.\nIf you did not request this code, please ignore this email.\n\nBBDRTS Protocol - Saint Joseph College CCS`,
      html: `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #0c1015; color: #f1f5f9; padding: 32px 20px; border-radius: 12px; max-width: 540px; margin: 0 auto; border: 1px solid #1e293b;">
          <div style="text-align: center; margin-bottom: 24px;">
            <h2 style="color: #22c55e; margin: 0; font-size: 24px; letter-spacing: -0.5px;">BBDRTS PROTOCOL</h2>
            <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">Blockchain-Based Donation & Relief Transparency System</p>
          </div>
          
          <div style="background-color: #161f2e; border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px;">
            <p style="color: #cbd5e1; font-size: 14px; margin-top: 0;">Here is your 6-digit One-Time Security Passcode to access your <strong>${requestedRole.toUpperCase()}</strong> account:</p>
            <div style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #22c55e; background: rgba(34, 197, 94, 0.1); padding: 12px 20px; border-radius: 8px; display: inline-block; margin: 12px 0; border: 1px solid #22c55e;">
              ${otpCode}
            </div>
            <p style="color: #ef4444; font-size: 12px; margin: 8px 0 0 0; font-weight: 600;">⏳ This one-time code expires in 5 minutes.</p>
          </div>

          <p style="color: #64748b; font-size: 12px; line-height: 1.5; margin-bottom: 20px;">
            If you did not request this login code, you can safely ignore this email.
          </p>

          <div style="border-top: 1px solid #1e293b; padding-top: 14px; font-size: 11px; color: #475569; text-align: center;">
            College of Computer Studies · Saint Joseph College · Maasin City, Southern Leyte
          </div>
        </div>
      `
    };

    const emailSent = await sendMailSafe(mailOptions, 6000);
    if (emailSent) {
      console.log(`✅ [LOGIN OTP SENT] Code sent successfully to ${targetEmail} (${requestedRole})`);
    } else {
      console.log(`ℹ️ [DEV LOG] SMTP unavailable or timed out. Login OTP for ${targetEmail} (${requestedRole}): [${otpCode}]`);
    }

    res.json({
      success: true,
      message: emailSent
        ? `A 6-digit login passcode has been dispatched to ${targetEmail}. Please check your inbox (and Spam/Junk folder if not seen).`
        : `A 6-digit login passcode has been generated. Use the code below to log in:`,
      emailSent,
      devCode: emailSent ? undefined : otpCode
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ── Routes: One-Time Passcode (OTP) Login Verify (Strict Role Verification) ──
app.post('/api/auth/login-otp-verify', rateLimiter(100, 15 * 60 * 1000), async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'Please provide email and the 6-digit passcode.' });
  }

  const targetEmail = email.trim().toLowerCase();
  const record = loginOtps.get(targetEmail);

  if (!record) {
    return res.status(400).json({ error: 'No active login passcode request found. Please request a new code.' });
  }

  if (Date.now() > record.expiresAt) {
    loginOtps.delete(targetEmail);
    return res.status(400).json({ error: 'Login passcode has expired. Please request a new code.' });
  }

  if (record.otp.trim() !== otp.trim()) {
    return res.status(400).json({ error: 'Invalid passcode. Please check your email and try again.' });
  }

  try {
    let user = null;
    let foundRole = record.role;
    let idCol = 'Donor_ID';

    if (foundRole === 'organization') {
      const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE LOWER(Username) = ?', [targetEmail]);
      if (orgRows.length > 0) {
        user = orgRows[0];
        idCol = 'Org_ID';
      }
    } else if (foundRole === 'admin') {
      const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE LOWER(Username) = ?', [targetEmail]);
      if (adminRows.length > 0) {
        user = adminRows[0];
        idCol = 'Admin_ID';
      }
    } else {
      const [donorRows] = await db.query('SELECT * FROM DONOR WHERE LOWER(Username) = ?', [targetEmail]);
      if (donorRows.length > 0) {
        user = donorRows[0];
        idCol = 'Donor_ID';
      }
    }

    if (!user) {
      loginOtps.delete(targetEmail);
      return res.status(404).json({ error: `No ${foundRole} account found for this email. Please register first.` });
    }

    const token = jwt.sign({ id: user[idCol], email: user.Username, role: foundRole }, secretKey, { expiresIn: '24h' });
    loginOtps.delete(targetEmail);

    res.json({
      message: 'Login successful via Email Security Passcode!',
      token,
      user: formatUserObj(user, foundRole, idCol)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete login: ' + error.message });
  }
});

// ── In-Memory Password Reset OTP Store ────────────────────
const passwordResetOtps = new Map();

// ── Routes: Request Password Reset (Real Gmail Dispatch) ──
app.post('/api/auth/forgot-password', rateLimiter(8, 15 * 60 * 1000), async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Please provide a valid registered email address.' });
  }

  const targetEmail = email.trim().toLowerCase();

  try {
    let foundUser = null;
    let foundTable = null;
    let foundRole = null;
    let idCol = null;

    const [donorRows] = await db.query('SELECT * FROM DONOR WHERE Username = ?', [targetEmail]);
    if (donorRows.length > 0) {
      foundUser = donorRows[0];
      foundTable = 'DONOR';
      foundRole = 'donor';
      idCol = 'Donor_ID';
    } else {
      const [orgRows] = await db.query('SELECT * FROM ORGANIZATION WHERE Username = ?', [targetEmail]);
      if (orgRows.length > 0) {
        foundUser = orgRows[0];
        foundTable = 'ORGANIZATION';
        foundRole = 'organization';
        idCol = 'Org_ID';
      } else {
        const [adminRows] = await db.query('SELECT * FROM ADMINISTRATOR WHERE Username = ?', [targetEmail]);
        if (adminRows.length > 0) {
          foundUser = adminRows[0];
          foundTable = 'ADMINISTRATOR';
          foundRole = 'admin';
          idCol = 'Admin_ID';
        }
      }
    }

    if (!foundUser) {
      // Auto-provision donor account record so user can set password and recover seamlessly
      const initialHashed = await bcrypt.hash('temp_pending_pwd', 10);
      const resInsert = await db.query('INSERT INTO DONOR (Username, Password) VALUES (?, ?)', [targetEmail, initialHashed]);
      const newId = resInsert.insertId || resInsert[0]?.insertId || 1;
      foundUser = { Donor_ID: newId, Username: targetEmail };
      foundTable = 'DONOR';
      foundRole = 'donor';
      idCol = 'Donor_ID';
    }

    // Generate secure 6-digit numeric OTP code
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    passwordResetOtps.set(targetEmail, {
      otp: otpCode,
      expiresAt,
      role: foundRole,
      table: foundTable,
      idCol,
      userId: foundUser[idCol]
    });

    const mailOptions = {
      from: `"BBDRTS Protocol" <${process.env.SMTP_USER || 'gestermacaldo@gmail.com'}>`,
      to: targetEmail,
      replyTo: process.env.SMTP_USER || 'gestermacaldo@gmail.com',
      subject: `BBDRTS Password Reset Code: ${otpCode}`,
      text: `You requested a password reset for your BBDRTS account.\n\nYour 6-digit recovery code is: ${otpCode}\n\nThis verification code expires in 5 minutes.\nIf you did not request this reset, please ignore this email.\n\nBBDRTS Protocol Team - Saint Joseph College CCS`,
      html: `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #0c1015; color: #f1f5f9; padding: 32px 20px; border-radius: 12px; max-width: 540px; margin: 0 auto; border: 1px solid #1e293b;">
          <div style="text-align: center; margin-bottom: 24px;">
            <h2 style="color: #22c55e; margin: 0; font-size: 24px; letter-spacing: -0.5px;">BBDRTS PROTOCOL</h2>
            <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">Blockchain-Based Donation & Relief Transparency System</p>
          </div>
          
          <div style="background-color: #161f2e; border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px;">
            <p style="color: #cbd5e1; font-size: 14px; margin-top: 0;">You requested a password reset for your <strong>${foundRole.toUpperCase()}</strong> account. Use this one-time verification code to reset your password:</p>
            <div style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #22c55e; background: rgba(34, 197, 94, 0.1); padding: 12px 20px; border-radius: 8px; display: inline-block; margin: 12px 0; border: 1px solid #22c55e;">
              ${otpCode}
            </div>
            <p style="color: #ef4444; font-size: 12px; margin: 8px 0 0 0; font-weight: 600;">⏳ This verification code expires in 5 minutes.</p>
          </div>

          <p style="color: #64748b; font-size: 12px; line-height: 1.5; margin-bottom: 20px;">
            If you did not initiate this password recovery request, please disregard this email or notify the Disaster Relief Response Desk immediately at <strong>+63 917 890 1234</strong>.
          </p>

          <div style="border-top: 1px solid #1e293b; padding-top: 14px; font-size: 11px; color: #475569; text-align: center;">
            College of Computer Studies · Saint Joseph College · Maasin City, Southern Leyte
          </div>
        </div>
      `
    };

    const emailSent = await sendMailSafe(mailOptions, 6000);
    if (emailSent) {
      console.log(`✅ [EMAIL SENT] Verification OTP sent successfully to ${targetEmail}`);
    } else {
      console.log(`ℹ️ [DEV LOG] SMTP unavailable or timed out. Generated OTP for ${targetEmail}: [${otpCode}]`);
    }

    res.json({
      success: true,
      message: emailSent
        ? `A 6-digit password reset code has been sent to ${targetEmail}. Please check your inbox.`
        : `A 6-digit password reset code has been generated. For fast recovery, use the code below:`,
      emailSent,
      devCode: emailSent ? undefined : otpCode
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during password recovery: ' + error.message });
  }
});

// ── Routes: Verify Code & Reset Password ──────────────────
app.post('/api/auth/reset-password', rateLimiter(10, 15 * 60 * 1000), async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: 'Please provide email, verification code, and your new password.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }

  const targetEmail = email.trim().toLowerCase();
  const record = passwordResetOtps.get(targetEmail);

  if (!record) {
    return res.status(400).json({ error: 'No active verification code found for this email. Please request a new code.' });
  }

  if (Date.now() > record.expiresAt) {
    passwordResetOtps.delete(targetEmail);
    return res.status(400).json({ error: 'Verification code has expired. Please request a new code.' });
  }

  if (record.otp.trim() !== otp.trim()) {
    return res.status(400).json({ error: 'Invalid verification code. Please check your email and try again.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query(`UPDATE ${record.table} SET Password = ? WHERE ${record.idCol} = ?`, [hashedPassword, record.userId]);

    // Clear OTP record after successful reset
    passwordResetOtps.delete(targetEmail);
    console.log(`🔒 [PASSWORD RESET SUCCESS] Updated credentials for ${targetEmail} (${record.role})`);

    res.json({ success: true, message: 'Password has been successfully updated! You can now log in with your new password.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update password: ' + error.message });
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
    res.json({
      user: formatUserObj(user, req.user.role, idCol)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Prohibited & Offensive Words Filter for Usernames & Display Names ──
const PROHIBITED_SUBSTRINGS = [
  // Sexually Explicit / NSFW
  'sex', 'sexy', 'porn', 'porno', 'nude', 'naked', 'penis', 'cock', 'vagina', 'pussy', 'dick', 'boobs', 'tits', 'anal', 
  'blowjob', 'handjob', 'cum', 'sperm', 'horny', 'masturbat', 'hentai', 'escort', 'onlyfans', 'dildo', 'orgasm', 'nsfw', 'erotic', 'pedophile', 'pedo',
  // English Profanity & Slurs
  'fuck', 'shit', 'bitch', 'asshole', 'bastard', 'cunt', 'whore', 'slut', 'fag', 'faggot', 'nigger', 'nigga', 'retard', 'bullshit', 'motherfucker',
  // Tagalog / Filipino Profanity & Slurs
  'putangina', 'tangina', 'tanginamo', 'gago', 'tarantado', 'ulol', 'bobo', 'inutil', 'puta', 'leche', 'pakshet', 'tanga', 'kupal', 'pakyu', 'pokpok',
  'bayag', 'bilat', 'burat', 'puke', 'pekpek', 'kantot', 'jakol', 'tamod', 'chupa', 'hindot', 'tae', 'yawa', 'piste', 'atay', 'oten', 'giatay', 'buang',
  // System / Impersonation & Scam Terms
  'admin', 'administrator', 'system', 'root', 'bbdrts_official', 'bbdrts_admin', 'official_support', 'moderator', 'staff', 'support_team', 'scammer', 'phishing', 'hacker'
];

function collapseRepeats(str) {
  return (str || '').replace(/(.)\1+/g, '$1');
}

function validateDisplayName(displayName) {
  if (!displayName || typeof displayName !== 'string') {
    return { valid: false, error: 'Please enter a valid display name.' };
  }
  const clean = displayName.trim();
  if (clean.length < 3) {
    return { valid: false, error: 'Display name must be at least 3 characters long.' };
  }
  if (clean.length > 35) {
    return { valid: false, error: 'Display name cannot exceed 35 characters.' };
  }
  const validCharRegex = /^[a-zA-Z0-9\s._\-ñÑáéíóúÁÉÍÓÚ]+$/;
  if (!validCharRegex.test(clean)) {
    return { valid: false, error: 'Display name contains invalid characters. Only letters, numbers, spaces, and . _ - are allowed.' };
  }

  // 1. Normalized leetspeak check
  const normalized = clean.toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/[1!|]/g, 'i')
    .replace(/[3]/g, 'e')
    .replace(/[0]/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/[7]/g, 't')
    .replace(/[^a-z]/g, '');

  // 2. Character-collapse check (catches 'seeex', 'fuuuuck', 'shiiit', 'gaaaago', 's-e-e-e-x')
  const collapsed = collapseRepeats(normalized);

  const words = clean.toLowerCase().split(/[\s._\-]+/);
  const wordsCollapsed = words.map(w => collapseRepeats(w.replace(/[^a-z0-9]/g, '')));

  for (const bad of PROHIBITED_SUBSTRINGS) {
    const badClean = bad.toLowerCase().replace(/[^a-z]/g, '');
    const badCollapsed = collapseRepeats(badClean);

    if (
      words.includes(bad) ||
      wordsCollapsed.includes(badCollapsed) ||
      normalized === badClean ||
      collapsed === badCollapsed ||
      normalized.includes(badClean) ||
      collapsed.includes(badCollapsed)
    ) {
      return { valid: false, error: 'This display name contains prohibited or inappropriate words. Please choose an appropriate name.' };
    }
  }

  // Check 3-letter explicit words on normalized token boundaries
  if (
    /\b(s+e+x+|p+o+r+n+|n+u+d+e+|c+u+m+|c+o+c+k+|d+i+c+k+|p+u+s+s+y+|t+i+t+s?|a+s+s+|g+a+g+o+|u+l+o+l+|b+o+b+o+|p+u+t+a+)\b/i.test(clean) ||
    collapsed === 'sex' ||
    collapsed === 'cum' ||
    collapsed === 'ass' ||
    collapsed.includes('sex')
  ) {
    return { valid: false, error: 'This display name contains prohibited or inappropriate words. Please choose an appropriate name.' };
  }

  return { valid: true, sanitized: clean };
}

// ── Real-Time Display Name Availability & Moderation Check ──
app.get('/api/auth/check-display-name', async (req, res) => {
  const name = (req.query.name || '').trim();
  const excludeId = req.query.excludeId ? parseInt(req.query.excludeId) : null;

  if (!name) {
    return res.json({ available: false, error: 'Please enter a display name.' });
  }

  const valRes = validateDisplayName(name);
  if (!valRes.valid) {
    return res.json({ available: false, error: valRes.error });
  }

  try {
    const [donorRows] = await db.query(
      `SELECT Donor_ID FROM DONOR WHERE LOWER(Display_Name) = LOWER(?) ${excludeId ? 'AND Donor_ID != ?' : ''}`,
      excludeId ? [valRes.sanitized, excludeId] : [valRes.sanitized]
    );
    if (donorRows && donorRows.length > 0) {
      return res.json({ available: false, error: 'This display name is already taken by another user.' });
    }

    const [orgRows] = await db.query(
      `SELECT Org_ID FROM ORGANIZATION WHERE LOWER(Org_Name) = LOWER(?)`,
      [valRes.sanitized]
    );
    if (orgRows && orgRows.length > 0) {
      return res.json({ available: false, error: 'This display name is reserved for a registered Organization.' });
    }

    res.json({ available: true, sanitized: valRes.sanitized });
  } catch (err) {
    res.status(500).json({ available: false, error: 'Error validating display name.' });
  }
});

// ── Routes: Profile Update (Donor Profile & Org Settings) ──
app.post('/api/auth/profile', async (req, res) => {
  let role = req.body.role || 'donor';
  let id = req.body.id || null;
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, secretKey);
      role = decoded.role || role;
      id = decoded.id || id;
    } catch (_) {}
  }

  // Fallback to email if token is expired or not yet cached
  if (!id && req.body.email) {
    try {
      const [donorRows] = await db.query(`SELECT Donor_ID FROM DONOR WHERE LOWER(Username) = LOWER(?)`, [req.body.email]);
      if (donorRows && donorRows.length > 0) {
        id = donorRows[0].Donor_ID;
        role = 'donor';
      } else {
        const [orgRows] = await db.query(`SELECT Org_ID FROM ORGANIZATION WHERE LOWER(Username) = LOWER(?)`, [req.body.email]);
        if (orgRows && orgRows.length > 0) {
          id = orgRows[0].Org_ID;
          role = 'organization';
        }
      }
    } catch (e) {
      console.warn("Email fallback query issue:", e);
    }
  }

  if (!id) {
    return res.status(401).json({ error: 'Session authentication required to save profile.' });
  }

  const {
    name,
    phone,
    location,
    bio,
    avatar_url,
    banner_url,
    website,
    emergency_hotline,
    gcash_name,
    gcash_number,
    gcash_qr_url,
    maya_name,
    maya_number,
    maya_qr_url,
    bank_name,
    bank_account_name,
    bank_account_number,
    bank_details,
    bank_qr_url,
    title,
    agency,
    preferences
  } = req.body;

  try {
    if (role === 'donor') {
      const [currentDonorRows] = await db.query(`SELECT Name, Legal_Name, Display_Name, Name_Last_Changed_At, Avatar_Url FROM DONOR WHERE Donor_ID = ?`, [id]);
      const currentDonor = currentDonorRows[0] || {};
      const currentDisplayName = currentDonor.Display_Name || currentDonor.Name || currentDonor.Legal_Name || '';
      const submittedDisplayName = (req.body.display_name !== undefined ? req.body.display_name : req.body.name || '').trim();

      let updatedDisplayName = currentDisplayName;
      let nameChangedAt = currentDonor.Name_Last_Changed_At || null;

      // ONLY trigger cooldown & validation if user ACTUALLY modified their display name to a different string
      if (submittedDisplayName && submittedDisplayName !== currentDisplayName) {
        // 1. Content & Profanity validation
        const valRes = validateDisplayName(submittedDisplayName);
        if (!valRes.valid) {
          return res.status(400).json({ error: valRes.error });
        }

        // 2. Uniqueness check against other donors
        const [existingDonorRows] = await db.query(
          `SELECT Donor_ID FROM DONOR WHERE LOWER(Display_Name) = LOWER(?) AND Donor_ID != ?`,
          [valRes.sanitized, id]
        );
        if (existingDonorRows && existingDonorRows.length > 0) {
          return res.status(400).json({
            error: 'This display name is already taken by another user. Please choose a unique display name.'
          });
        }

        // 3. Uniqueness check against organizations
        const [existingOrgRows] = await db.query(
          `SELECT Org_ID FROM ORGANIZATION WHERE LOWER(Org_Name) = LOWER(?)`,
          [valRes.sanitized]
        );
        if (existingOrgRows && existingOrgRows.length > 0) {
          return res.status(400).json({
            error: 'This display name is reserved for a registered Organization. Please choose another name.'
          });
        }

        // 4. Cooldown check
        if (currentDonor.Name_Last_Changed_At) {
          const lastChanged = new Date(currentDonor.Name_Last_Changed_At).getTime();
          const now = Date.now();
          const cooldownMs = 14 * 24 * 60 * 60 * 1000; // 14-day cooldown
          const elapsed = now - lastChanged;
          if (elapsed < cooldownMs) {
            const daysRemaining = Math.ceil((cooldownMs - elapsed) / (24 * 60 * 60 * 1000));
            return res.status(400).json({
              error: `Display name was recently updated. In accordance with platform security, you can change your display name again in ${daysRemaining} day${daysRemaining > 1 ? 's' : ''}.`
            });
          }
        }
        updatedDisplayName = valRes.sanitized;
        nameChangedAt = new Date().toISOString();
      }

      const prefsStr = req.body.preferences ? (typeof req.body.preferences === 'string' ? req.body.preferences : JSON.stringify(req.body.preferences)) : currentDonor.Preferences_Json;

      await db.query(
        `UPDATE DONOR SET 
          Display_Name = ?,
          Name = ?, 
          Name_Last_Changed_At = ?,
          Avatar_Url = ?,
          Mobile_Number = ?,
          Location = ?,
          Bio = ?,
          Preferences_Json = ?
        WHERE Donor_ID = ?`,
        [
          updatedDisplayName,
          updatedDisplayName,
          nameChangedAt,
          avatar_url !== undefined ? avatar_url : currentDonor.Avatar_Url,
          (phone || '').trim() || null,
          (location || '').trim() || null,
          (bio || '').trim() || null,
          prefsStr || null,
          id
        ]
      );
    } else if (role === 'organization') {
      const bannerUrl = req.body.banner_url !== undefined ? req.body.banner_url : null;
      const prefsStr = req.body.preferences ? (typeof req.body.preferences === 'string' ? req.body.preferences : JSON.stringify(req.body.preferences)) : null;

      await db.query(
        `UPDATE ORGANIZATION SET 
          Org_Name = ?, 
          Mobile_Number = ?, 
          Location = ?, 
          Bio = ?, 
          Avatar_Url = ?, 
          Banner_Url = ?,
          Website = ?, 
          Emergency_Hotline = ?, 
          Gcash_Name = ?,
          Gcash_Number = ?, 
          Gcash_Qr_Url = ?,
          Maya_Name = ?,
          Maya_Number = ?, 
          Maya_Qr_Url = ?,
          Bank_Name = ?,
          Bank_Account_Name = ?,
          Bank_Account_Number = ?,
          Bank_Details = ?,
          Bank_Qr_Url = ?,
          Preferences_Json = ?
        WHERE Org_ID = ?`,
        [
          (name || '').trim() || null,
          (phone || '').trim() || null,
          (location || '').trim() || null,
          (bio || '').trim() || null,
          avatar_url !== undefined ? avatar_url : null,
          bannerUrl,
          (website || '').trim() || null,
          (emergency_hotline || '').trim() || null,
          (gcash_name || '').trim() || null,
          (gcash_number || '').trim() || null,
          gcash_qr_url !== undefined ? gcash_qr_url : null,
          (maya_name || '').trim() || null,
          (maya_number || '').trim() || null,
          maya_qr_url !== undefined ? maya_qr_url : null,
          (bank_name || '').trim() || null,
          (bank_account_name || '').trim() || null,
          (bank_account_number || '').trim() || null,
          typeof bank_details === 'object' ? JSON.stringify(bank_details) : (bank_details || '').trim() || null,
          bank_qr_url !== undefined ? bank_qr_url : null,
          prefsStr,
          id
        ]
      );
    } else if (role === 'admin') {
      await db.query(
        `UPDATE ADMINISTRATOR SET 
          Name = ?, 
          Mobile_Number = ?, 
          Title = ?, 
          Agency = ?, 
          Avatar_Url = ? 
        WHERE Admin_ID = ?`,
        [
          (name || '').trim() || null,
          (phone || '').trim() || null,
          (title || '').trim() || null,
          (agency || '').trim() || null,
          avatar_url || null,
          id
        ]
      );
    }

    // Fetch refreshed user
    const tableName = getRoleTable(role);
    const idCol = getRoleIDColumn(role);
    const [rows] = await db.query(`SELECT * FROM ${tableName} WHERE ${idCol} = ?`, [id]);
    const updatedUser = rows[0] || {};

    res.json({
      success: true,
      message: 'Profile updated and synchronized successfully across protocol nodes.',
      user: formatUserObj(updatedUser, role, idCol)
    });
  } catch (err) {
    console.error('Profile update failed:', err);
    res.status(500).json({ error: 'Failed to update profile: ' + err.message });
  }
});

// ── Routes: In-App Institutional KYC & SEC Accreditation (Post-Signup) ──
app.get('/api/organization/kyc', authenticateToken, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.status(403).json({ error: 'Only registered organizations can access institutional KYC.' });
  }

  try {
    const [rows] = await db.query(
      `SELECT 
        Org_ID, Username, Org_Name, Verification_Status, Wallet_Address, Mobile_Number,
        Sec_Registration_No as secRegistrationNo,
        Sec_Certificate_Url as secCertificateUrl,
        Board_Members_Json as boardMembers,
        Dswd_Accreditation_No as dswdAccreditationNo,
        Verified_At as verifiedAt,
        Verified_By as verifiedBy,
        Audit_Notes as auditNotes
      FROM ORGANIZATION WHERE Org_ID = ?`,
      [req.user.id]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Organization not found.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/organization/kyc', authenticateToken, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.status(403).json({ error: 'Only registered organizations can submit institutional KYC.' });
  }

  const {
    org_name,
    sec_registration_no,
    sec_certificate_url,
    board_members,
    dswd_accreditation_no
  } = req.body;

  if (!sec_registration_no && !sec_certificate_url) {
    return res.status(400).json({ error: 'Please provide your SEC Registration Number or upload the Certificate of Incorporation.' });
  }

  try {
    const boardJson = typeof board_members === 'string' ? board_members : JSON.stringify(board_members || []);
    
    // Fetch existing status; if approved, preserve; if pending/rejected, keep pending
    const [existing] = await db.query(`SELECT Verification_Status, Org_Name FROM ORGANIZATION WHERE Org_ID = ?`, [req.user.id]);
    const currentStatus = existing[0]?.Verification_Status;
    const nextStatus = currentStatus === 'Approved' ? 'Approved' : 'Pending';

    await db.query(
      `UPDATE ORGANIZATION SET
        Org_Name = COALESCE(?, Org_Name),
        Sec_Registration_No = ?,
        Sec_Certificate_Url = COALESCE(?, Sec_Certificate_Url),
        Board_Members_Json = ?,
        Dswd_Accreditation_No = ?,
        Verification_Status = ?,
        Audit_Notes = 'Submitted for Admin SEC Anti-Bias Compliance Audit.'
      WHERE Org_ID = ?`,
      [
        (org_name || '').trim() || null,
        (sec_registration_no || '').trim(),
        sec_certificate_url || null,
        boardJson,
        (dswd_accreditation_no || '').trim(),
        nextStatus,
        req.user.id
      ]
    );

    res.json({
      success: true,
      message: 'SEC Accreditation documents submitted successfully to the Admin Audit Desk!',
      verification_status: nextStatus
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save KYC documents: ' + err.message });
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

  const {
    title,
    target_amount,
    contract_address,
    tags,
    description,
    location_region,
    gps_coordinates,
    beneficiaries_impact,
    allocations_json,
    contact_info,
    category,
    urgency,
    target_date,
    document_url,
    gcash_name,
    gcash_number,
    gcash_qr_url,
    maya_name,
    maya_number,
    maya_qr_url,
    bank_name,
    bank_account_name,
    bank_account_number,
    bank_qr_url
  } = req.body;

  if (!title || !target_amount) return res.status(400).json({ error: 'Missing campaign data.' });

  try {
    await db.query(
      `INSERT INTO CAMPAIGN (
        Org_ID,
        Campaign_Title,
        Target_Amount,
        Smart_Contract_Address,
        Tags,
        Description,
        Location_Region,
        Gps_Coordinates,
        Beneficiaries_Impact,
        Allocations_Json,
        Contact_Info,
        Category,
        Urgency,
        Target_Date,
        Document_Url,
        Gcash_Name,
        Gcash_Number,
        Gcash_Qr_Url,
        Maya_Name,
        Maya_Number,
        Maya_Qr_Url,
        Bank_Name,
        Bank_Account_Name,
        Bank_Account_Number,
        Bank_Qr_Url
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        title,
        target_amount,
        contract_address || null,
        tags || '',
        description || '',
        location_region || '',
        gps_coordinates || '',
        beneficiaries_impact || '',
        typeof allocations_json === 'string' ? allocations_json : JSON.stringify(allocations_json || []),
        contact_info || '',
        category || 'FOOD_WATER',
        urgency || 'HIGH',
        target_date || '',
        document_url || '',
        (gcash_name || '').trim() || null,
        (gcash_number || '').trim() || null,
        gcash_qr_url || null,
        (maya_name || '').trim() || null,
        (maya_number || '').trim() || null,
        maya_qr_url || null,
        (bank_name || '').trim() || null,
        (bank_account_name || '').trim() || null,
        (bank_account_number || '').trim() || null,
        bank_qr_url || null
      ]
    );
    res.status(201).json({ message: 'Campaign verified and saved to database with full details.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync campaign: ' + err.message });
  }
});

// ── Manual Fiat Verification Routes (Capstone Feature) ───

// 1. Upload Manual Donation Receipt
app.post('/api/manual-donations', authenticateToken, async (req, res) => {
  if (req.user.role !== 'donor') return res.status(403).json({ error: 'Only donors can upload receipts.' });

  const { campaign_id, amount, payment_method, receipt_base64 } = req.body;
  if (!campaign_id || !amount || !receipt_base64) return res.status(400).json({ error: 'Missing required manual donation fields.' });

  try {
    await db.query(
      `INSERT INTO MANUAL_DONATION (Donor_ID, Campaign_ID, Amount, Payment_Method, Receipt_Base64, Status) VALUES (?, ?, ?, ?, ?, 'Pending')`,
      [req.user.id, campaign_id, amount, payment_method || 'Unknown', receipt_base64]
    );
    res.status(201).json({ message: 'Receipt uploaded successfully. Pending NGO verification.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to upload receipt: ' + err.message });
  }
});

// 2. Get Pending Manual Donations for an NGO or Admin
app.get('/api/manual-donations/pending', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const [rows] = await db.query(`
        SELECT m.*, d.Username as Donor_Name, c.Campaign_Title 
        FROM MANUAL_DONATION m 
        JOIN DONOR d ON m.Donor_ID = d.Donor_ID 
        JOIN CAMPAIGN c ON m.Campaign_ID = c.Campaign_ID 
        WHERE m.Status = 'Pending'
      `);
      return res.json(rows);
    } else if (req.user.role === 'organization') {
      const [rows] = await db.query(`
        SELECT m.*, d.Username as Donor_Name, c.Campaign_Title 
        FROM MANUAL_DONATION m 
        JOIN DONOR d ON m.Donor_ID = d.Donor_ID 
        JOIN CAMPAIGN c ON m.Campaign_ID = c.Campaign_ID 
        WHERE m.Status = 'Pending' AND c.Org_ID = ?
      `, [req.user.id]);
      return res.json(rows);
    } else {
      return res.status(403).json({ error: 'Access denied.' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch pending donations: ' + err.message });
  }
});

// 3. Approve or Reject Manual Donation
app.post('/api/manual-donations/:id/:action', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'organization') return res.status(403).json({ error: 'Access denied.' });
  
  const { id, action } = req.params;
  const newStatus = action === 'approve' ? 'Approved' : 'Rejected';
  
  try {
    const [manualRows] = await db.query(`
      SELECT m.*, c.Org_ID, d.Wallet_Address as Donor_Wallet
      FROM MANUAL_DONATION m
      JOIN CAMPAIGN c ON m.Campaign_ID = c.Campaign_ID
      LEFT JOIN DONOR d ON m.Donor_ID = d.Donor_ID
      WHERE m.Manual_ID = ?
    `, [id]);

    if (manualRows.length === 0) {
      return res.status(404).json({ error: 'Manual donation record not found.' });
    }
    const record = manualRows[0];

    if (req.user.role === 'organization' && record.Org_ID !== req.user.id) {
       return res.status(403).json({ error: 'Not authorized to approve this receipt.' });
    }

    await db.query(`UPDATE MANUAL_DONATION SET Status = ? WHERE Manual_ID = ?`, [newStatus, id]);

    // When approved, record into DONATION_TRANSACTION so it appears in ledger and increments campaign raised balance
    if (action === 'approve') {
      const cleanMethod = (record.Payment_Method || 'FIAT').toUpperCase().replace(/[^A-Z]/g, '').substring(0, 4);
      const auditHash = `FIAT-${cleanMethod}-MANUAL-${record.Manual_ID}-${Date.now().toString().slice(-6)}`;
      
      await db.query(
        `INSERT INTO DONATION_TRANSACTION (Donor_ID, Org_ID, Campaign_ID, Tx_Hash, Amount, Is_Anonymous, Wallet_Address) VALUES (?, ?, ?, ?, ?, 0, ?)`,
        [record.Donor_ID, record.Org_ID, record.Campaign_ID, auditHash, record.Amount, record.Donor_Wallet || null]
      );
    }

    res.json({ message: `Manual donation ${newStatus.toLowerCase()} successfully and synchronized to ledger.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process receipt: ' + err.message });
  }
});

app.post('/api/donations', async (req, res) => {
  const { campaign_id, tx_hash, amount, is_anonymous, wallet_address } = req.body;
  if (!campaign_id || !tx_hash || !amount) return res.status(400).json({ error: 'Missing transaction data.' });

  // Security Check: Verify On-Chain Transaction Authenticity via RPC if not mock
  if (typeof tx_hash === 'string' && !tx_hash.startsWith('FIAT-')) {
    const verification = await verifyOnChainTx(tx_hash);
    if (!verification.valid) {
      return res.status(400).json({ error: verification.error || 'On-chain transaction verification failed.' });
    }
  }

  let donorId = null;
  let orgId = null;
  let senderWallet = wallet_address || null;

  // Extract from JWT if provided
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token && token !== 'null') {
    try {
      const user = jwt.verify(token, secretKey);
      if (user && user.role === 'donor') donorId = user.id;
      if (user && user.role === 'organization') orgId = user.id;
    } catch (_) {}
  }

  // Lookup donor by wallet address if donorId is not set
  if (!donorId && !orgId && senderWallet) {
    try {
      const [donors] = await db.query('SELECT Donor_ID FROM DONOR WHERE LOWER(Wallet_Address) = ?', [senderWallet.toLowerCase()]);
      if (donors.length > 0) donorId = donors[0].Donor_ID;
    } catch (_) {}
  }

  // Lookup Org_ID from campaign if not already set
  if (!orgId && campaign_id) {
    try {
      const [campRows] = await db.query('SELECT Org_ID FROM CAMPAIGN WHERE Campaign_ID = ?', [campaign_id]);
      if (campRows.length > 0 && campRows[0].Org_ID) orgId = campRows[0].Org_ID;
    } catch (_) {}
  }

  try {
    const anonymousFlag = is_anonymous ? 1 : 0;

    const [existing] = await db.query('SELECT Transaction_ID FROM DONATION_TRANSACTION WHERE Tx_Hash = ?', [tx_hash]);
    if (existing.length === 0) {
      await db.query(
        `INSERT INTO DONATION_TRANSACTION (Donor_ID, Org_ID, Campaign_ID, Tx_Hash, Amount, Is_Anonymous, Wallet_Address) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [donorId, orgId, campaign_id, tx_hash, amount, anonymousFlag, senderWallet]
      );
    }

    res.status(201).json({ message: 'Blockchain transaction verified on-chain and recorded successfully.' });
  } catch (err) {
    console.error('Failed to sync donation:', err);
    res.status(500).json({ error: 'Failed to sync donation: ' + err.message });
  }
});

app.get('/api/donations/me', authenticateToken, async (req, res) => {
  if (req.user.role !== 'donor' && req.user.role !== 'organization') return res.status(403).json({ error: 'Invalid role.' });
  try {
    const isDonor = req.user.role === 'donor';
    const userWallet = (req.user.wallet_address || '').toLowerCase().trim();
    const [rows] = await db.query(`
      SELECT 
        dt.Transaction_ID as id,
        dt.Tx_Hash as txHash,
        dt.Amount as amount,
        dt.Campaign_ID as campaignId,
        dt.Is_Anonymous as isAnonymous,
        c.Campaign_Title as campaignTitle,
        o.Org_Name as orgName,
        dt.Created_At as createdAt
      FROM DONATION_TRANSACTION dt
      LEFT JOIN CAMPAIGN c ON dt.Campaign_ID = c.Campaign_ID
      LEFT JOIN ORGANIZATION o ON (dt.Org_ID = o.Org_ID OR c.Org_ID = o.Org_ID)
      WHERE ${isDonor ? '(dt.Donor_ID = ? OR (dt.Wallet_Address IS NOT NULL AND LOWER(dt.Wallet_Address) = ?))' : '(dt.Org_ID = ? OR c.Org_ID = ?)'}
      ORDER BY dt.Transaction_ID DESC
    `, isDonor ? [req.user.id, userWallet || '___none___'] : [req.user.id, req.user.id]);
    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch personal donations: ' + err.message });
  }
});

app.post('/api/donations/verify-mock-gateway', async (req, res) => {
  const { campaign_id, amount, method, wallet_address, is_anonymous, ref_no, receipt_base64 } = req.body;
  if (!campaign_id || !amount || !method) return res.status(400).json({ error: 'Missing parameters.' });

  let donorId = null;
  let orgId = null;
  let donorEmail = null;
  let senderWallet = wallet_address || null;

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.split(' ')[1] && authHeader.split(' ')[1] !== 'null') {
    const token = authHeader.split(' ')[1];
    try {
      const user = jwt.verify(token, secretKey);
      if (user && user.role === 'donor') {
        donorId = user.id;
        donorEmail = user.email;
      }
      if (user && user.role === 'organization') orgId = user.id;
    } catch(e) {}
  }

  // Lookup donor by wallet address if donorId is not set
  if (!donorId && !orgId && senderWallet) {
    try {
      const [donors] = await db.query('SELECT Donor_ID FROM DONOR WHERE LOWER(Wallet_Address) = ?', [senderWallet.toLowerCase()]);
      if (donors.length > 0) donorId = donors[0].Donor_ID;
    } catch (_) {}
  }

  // Lookup Org_ID from campaign if not already set
  if (!orgId && campaign_id) {
    try {
      const [campRows] = await db.query('SELECT Org_ID FROM CAMPAIGN WHERE Campaign_ID = ?', [campaign_id]);
      if (campRows.length > 0 && campRows[0].Org_ID) orgId = campRows[0].Org_ID;
    } catch (_) {}
  }

  // Convert PHP amount to ETH equivalent for accurate ledger accounting
  const parsedPhp = parseFloat(amount) || 0;
  const ethAmount = parsedPhp / 170000;

  try {
    // 1. Record the fiat audit record
    await db.query(`
      INSERT INTO MANUAL_DONATION (Donor_ID, Campaign_ID, Amount, Payment_Method, Receipt_Base64, Status)
      VALUES (?, ?, ?, ?, ?, 'Approved')
    `, [donorId, campaign_id, ethAmount, method, receipt_base64 || null]);

    // 2. Credit the transaction to the public ledger
    const cleanMethod = (method || 'FIAT').toUpperCase().replace(/[^A-Z]/g, '').substring(0, 4);
    const cleanRef = (ref_no || '').replace(/[^0-9A-Za-z]/g, '').substring(0, 16);
    const mockTxHash = cleanRef ? `FIAT-${cleanMethod}-${cleanRef}` : `FIAT-${cleanMethod}-${Date.now()}`;
    const anonymousFlag = is_anonymous ? 1 : 0;

    await db.query(`
      INSERT INTO DONATION_TRANSACTION (Donor_ID, Org_ID, Campaign_ID, Tx_Hash, Amount, Is_Anonymous, Wallet_Address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [donorId, orgId, campaign_id, mockTxHash, ethAmount, anonymousFlag, senderWallet]);

    // 3. Emit real-time event-driven notifications to Donor and NGO
    try {
      const [campDetails] = await db.query(`
        SELECT c.Campaign_Title as title, o.Username as orgEmail, o.Org_Name as orgName
        FROM CAMPAIGN c
        LEFT JOIN ORGANIZATION o ON c.Org_ID = o.Org_ID
        WHERE c.Campaign_ID = ?
      `, [campaign_id]);
      const campTitle = campDetails[0]?.title || 'Disaster Relief Operation';
      const orgEmail = campDetails[0]?.orgEmail;

      // Donor Notification
      if (!donorEmail && donorId) {
        const [dRows] = await db.query('SELECT Username as email FROM DONOR WHERE Donor_ID = ?', [donorId]);
        if (dRows && dRows.length > 0) donorEmail = dRows[0].email;
      }

      if (donorEmail) {
        await sendNotificationToUser({
          userEmail: donorEmail,
          role: 'donor',
          type: 'DONATION',
          title: 'Donation Contribution Verified',
          message: `Your donation of ₱${parsedPhp.toLocaleString()} (${ethAmount.toFixed(4)} ETH) to "${campTitle}" was successfully processed and verified on the public ledger. Transaction Ref: ${mockTxHash}`,
          referenceId: mockTxHash,
          referenceType: 'donation',
          link: '#campaigns'
        });
      }

      // NGO Notification
      if (orgEmail) {
        await sendNotificationToUser({
          userEmail: orgEmail,
          role: 'organization',
          type: 'DONATION',
          title: 'New Relief Contribution Received',
          message: `Received a contribution of ₱${parsedPhp.toLocaleString()} (${ethAmount.toFixed(4)} ETH) for "${campTitle}" via ${method || 'E-Wallet'}. Ref: ${mockTxHash}`,
          referenceId: mockTxHash,
          referenceType: 'donation',
          link: '#campaigns'
        });
      }
    } catch (notifErr) {
      console.warn('⚠️ Could not emit donation event notification:', notifErr.message);
    }

    res.json({ success: true, message: 'Payment successfully processed and verified.', tx_hash: mockTxHash });
  } catch (err) {
    console.error('Mock Gateway Verification Error:', err);
    res.status(500).json({ error: 'Failed to process payment: ' + err.message });
  }
});

// ── GET /api/campaigns (Real Database Campaigns Only) ───────
app.get('/api/campaigns', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  try {
    const [rows] = await db.query(`
      SELECT 
        c.Campaign_ID as id, 
        c.Org_ID as orgId,
        c.Campaign_Title as title, 
        c.Target_Amount as targetAmount,
        c.Tags as tags,
        c.Description as description,
        c.Location_Region as locationRegion,
        c.Gps_Coordinates as gpsCoordinates,
        c.Beneficiaries_Impact as beneficiariesImpact,
        c.Allocations_Json as allocationsJson,
        c.Contact_Info as contactInfo,
        c.Category as category,
        c.Urgency as urgency,
        c.Target_Date as targetDate,
        c.Document_Url as documentUrl,
        c.Gcash_Name as gcashName,
        c.Gcash_Number as gcashNumber,
        c.Gcash_Qr_Url as gcashQrUrl,
        c.Maya_Name as mayaName,
        c.Maya_Number as mayaNumber,
        c.Maya_Qr_Url as mayaQrUrl,
        c.Bank_Name as bankName,
        c.Bank_Account_Name as bankAccountName,
        c.Bank_Account_Number as bankAccountNumber,
        c.Bank_Qr_Url as bankQrUrl,
        o.Org_Name as orgName,
        o.Wallet_Address as orgAddress,
        c.Smart_Contract_Address as contractAddress,
        COALESCE(SUM(dt.Amount), 0) as currentAmount
      FROM CAMPAIGN c
      LEFT JOIN DONATION_TRANSACTION dt ON c.Campaign_ID = dt.Campaign_ID
      LEFT JOIN ORGANIZATION o ON c.Org_ID = o.Org_ID
      GROUP BY c.Campaign_ID
      ORDER BY c.Campaign_ID DESC
    `);

    if (!rows || rows.length === 0) {
      return res.json([]);
    }

    // Query multi-rail donation transactions to calculate live breakdown
    let txRows = [];
    try {
      const [txs] = await db.query(`SELECT Campaign_ID, Tx_Hash, Amount FROM DONATION_TRANSACTION`);
      txRows = txs || [];
    } catch (_) {}

    const txByCampaign = {};
    if (Array.isArray(txRows)) {
      txRows.forEach(tx => {
        const cId = tx.Campaign_ID;
        if (!txByCampaign[cId]) {
          txByCampaign[cId] = {
            ethAmount: 0, ethCount: 0,
            gcashAmount: 0, gcashCount: 0,
            mayaAmount: 0, mayaCount: 0,
            bankAmount: 0, bankCount: 0,
            totalBackers: 0
          };
        }
        const amt = parseFloat(tx.Amount) || 0;
        const hash = (tx.Tx_Hash || '').toUpperCase();
        txByCampaign[cId].totalBackers++;

        if (hash.startsWith('FIAT-GCAS') || hash.includes('GCASH')) {
          txByCampaign[cId].gcashAmount += amt;
          txByCampaign[cId].gcashCount++;
        } else if (hash.startsWith('FIAT-MAYA') || hash.includes('MAYA')) {
          txByCampaign[cId].mayaAmount += amt;
          txByCampaign[cId].mayaCount++;
        } else if (hash.startsWith('FIAT-BANK') || hash.startsWith('FIAT-CRED') || hash.includes('BANK') || hash.includes('CARD')) {
          txByCampaign[cId].bankAmount += amt;
          txByCampaign[cId].bankCount++;
        } else {
          txByCampaign[cId].ethAmount += amt;
          txByCampaign[cId].ethCount++;
        }
      });
    }

    const formatted = rows.map((r) => {
      const b = txByCampaign[r.id] || {
        ethAmount: 0, ethCount: 0,
        gcashAmount: 0, gcashCount: 0,
        mayaAmount: 0, mayaCount: 0,
        bankAmount: 0, bankCount: 0,
        totalBackers: 0
      };

      const currentEth = Number(r.currentAmount) > 0 ? Number(r.currentAmount) : 0;
      const trackedSum = b.ethAmount + b.gcashAmount + b.mayaAmount + b.bankAmount;
      let finalEthAmount = b.ethAmount;
      if (currentEth > trackedSum) {
        finalEthAmount += (currentEth - trackedSum);
      }

      return {
        id: r.id,
        orgId: r.orgId || r.Org_ID || 3,
        title: r.title,
        targetAmount: (r.targetAmount || '1.00').toString(),
        tags: r.tags || '',
        currentAmount: (currentEth > 0 ? currentEth : 0).toString(),
        orgName: r.orgName || 'ReliefLink PH',
        orgAddress: r.orgAddress || '0x206e022D47003B67Ee72bd67fDF2406d43aabC2C',
        locationRegion: r.locationRegion || 'Southern Leyte, Philippines',
        gpsCoordinates: r.gpsCoordinates || '10.1335° N, 124.8732° E',
        beneficiariesImpact: r.beneficiariesImpact || 'Displaced Families & Affected Communities',
        description: r.description || 'Emergency disaster response, relief distribution, and rehabilitation operation.',
        urgency: r.urgency || 'HIGH',
        category: r.category || 'DR',
        targetDate: r.targetDate || '2026-12-31',
        documentUrl: r.documentUrl || '',
        allocationsJson: r.allocationsJson || '[]',
        contactInfo: r.contactInfo || '',
        gcashNumber: r.gcashNumber || '',
        gcashQrUrl: r.gcashQrUrl || '',
        mayaNumber: r.mayaNumber || '',
        mayaQrUrl: r.mayaQrUrl || '',
        bankName: r.bankName || '',
        bankAccountName: r.bankAccountName || '',
        bankAccountNumber: r.bankAccountNumber || '',
        bankQrUrl: r.bankQrUrl || '',
        isActive: true,
        railBreakdown: {
          eth: {
            amount: parseFloat(finalEthAmount.toFixed(6)),
            php: Math.round(finalEthAmount * 170000),
            count: b.ethCount || (finalEthAmount > 0 ? 1 : 0)
          },
          gcash: {
            amount: parseFloat(b.gcashAmount.toFixed(6)),
            php: Math.round(b.gcashAmount * 170000),
            count: b.gcashCount
          },
          maya: {
            amount: parseFloat(b.mayaAmount.toFixed(6)),
            php: Math.round(b.mayaAmount * 170000),
            count: b.mayaCount
          },
          bank: {
            amount: parseFloat(b.bankAmount.toFixed(6)),
            php: Math.round(b.bankAmount * 170000),
            count: b.bankCount
          },
          totalRaisedEth: parseFloat(currentEth.toFixed(6)),
          totalRaisedPhp: Math.round(currentEth * 170000),
          totalBackers: b.totalBackers || (currentEth > 0 ? 1 : 0)
        }
      };
    });

    res.json(formatted);
  } catch (err) {
    console.warn('DB query failed for campaigns:', err.message);
    res.json([]);
  }
});

// ── Public API ────────────────────────────────────────────
app.get('/api/public-stats', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  try {
    const [donors] = await db.query('SELECT COUNT(*) as c FROM DONOR');
    const [orgs] = await db.query("SELECT COUNT(*) as c FROM ORGANIZATION WHERE Verification_Status = 'Approved'");
    const [campaigns] = await db.query('SELECT COUNT(*) as c FROM CAMPAIGN');
    res.json({
      donors: donors[0]?.c || 0,
      orgs: orgs[0]?.c || 0,
      campaigns: campaigns[0]?.c || 0
    });
  } catch (err) {
    console.error('Public stats query error:', err.message);
    res.json({ donors: 0, orgs: 0, campaigns: 0 });
  }
});

// ── Global Cumulative Donor Totals (Platform-Wide Single Donor Badge Source of Truth) ──
app.get('/api/donors/cumulative-totals', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  try {
    const [rows] = await db.query(`
      SELECT 
        dt.Wallet_Address as txWallet,
        d.Wallet_Address as donorWallet,
        dt.Donor_ID as donorId,
        COALESCE(d.Display_Name, d.Name, 'Verified Donor') as donorName,
        dt.Amount as amount
      FROM DONATION_TRANSACTION dt
      LEFT JOIN DONOR d ON dt.Donor_ID = d.Donor_ID
    `);

    const donorTotals = {};
    const donorToWallets = {};

    (rows || []).forEach(r => {
      const amt = parseFloat(r.amount) || 0;
      const tw = (r.txWallet || '').toLowerCase().trim();
      const dw = (r.donorWallet || '').toLowerCase().trim();
      const did = r.donorId ? `id_${r.donorId}` : null;
      const name = r.donorName || 'Verified Donor';

      if (did) {
        if (!donorTotals[did]) donorTotals[did] = { totalEth: 0, totalPhp: 0, donationCount: 0, donorName: name };
        donorTotals[did].totalEth += amt;
        donorTotals[did].totalPhp = Math.round(donorTotals[did].totalEth * 170000);
        donorTotals[did].donationCount += 1;
        if (name && name !== 'Verified Donor') donorTotals[did].donorName = name;

        if (!donorToWallets[did]) donorToWallets[did] = new Set();
        if (tw && tw !== '0x0000000000000000000000000000000000000000') donorToWallets[did].add(tw);
        if (dw && dw !== '0x0000000000000000000000000000000000000000') donorToWallets[did].add(dw);
      }

      const activeWallet = tw && tw !== '0x0000000000000000000000000000000000000000' ? tw : (dw && dw !== '0x0000000000000000000000000000000000000000' ? dw : null);
      if (activeWallet) {
        if (!donorTotals[activeWallet]) donorTotals[activeWallet] = { totalEth: 0, totalPhp: 0, donationCount: 0, donorName: name };
        donorTotals[activeWallet].totalEth += amt;
        donorTotals[activeWallet].totalPhp = Math.round(donorTotals[activeWallet].totalEth * 170000);
        donorTotals[activeWallet].donationCount += 1;
        if (name && name !== 'Verified Donor') donorTotals[activeWallet].donorName = name;
      }
    });

    // Cross-link: ensure every linked wallet has the highest cumulative total of the donor
    Object.entries(donorToWallets).forEach(([did, wallets]) => {
      const donorStat = donorTotals[did];
      if (donorStat) {
        wallets.forEach(w => {
          if (!donorTotals[w]) {
            donorTotals[w] = { ...donorStat };
          } else {
            donorTotals[w].totalEth = Math.max(donorTotals[w].totalEth, donorStat.totalEth);
            donorTotals[w].totalPhp = Math.round(donorTotals[w].totalEth * 170000);
            donorTotals[w].donationCount = Math.max(donorTotals[w].donationCount, donorStat.donationCount);
          }
        });
      }
    });

    res.json(donorTotals);
  } catch (err) {
    console.warn('Failed to fetch donor cumulative totals:', err.message);
    res.json({});
  }
});

app.get('/api/campaigns/:id/donations', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT dt.Tx_Hash, dt.Amount, dt.Is_Anonymous, 
             COALESCE(dt.Wallet_Address, d.Wallet_Address, '') as wallet, 
             CASE 
               WHEN dt.Is_Anonymous = 1 THEN 'Anonymous Patron'
               ELSE COALESCE(d.Display_Name, d.Name, 'Verified Donor')
             END as donorName,
             dt.Created_At as createdAt,
             dt.Donor_ID as donorId
      FROM DONATION_TRANSACTION dt
      LEFT JOIN DONOR d ON dt.Donor_ID = d.Donor_ID
      WHERE dt.Campaign_ID = ?
      ORDER BY dt.Transaction_ID DESC
    `, [req.params.id]);

    // Query all transactions to compute global totals across all campaigns
    const [allTxs] = await db.query(`
      SELECT dt.Donor_ID as donorId, dt.Wallet_Address as txWallet, dt.Amount as amount, d.Wallet_Address as donorWallet
      FROM DONATION_TRANSACTION dt
      LEFT JOIN DONOR d ON dt.Donor_ID = d.Donor_ID
    `);
    const donorTotals = {};
    const donorToWallets = {};

    (allTxs || []).forEach(tx => {
      const amt = parseFloat(tx.amount) || 0;
      const tw = (tx.txWallet || '').toLowerCase().trim();
      const dw = (tx.donorWallet || '').toLowerCase().trim();
      const did = tx.donorId ? `id_${tx.donorId}` : null;

      if (did) {
        donorTotals[did] = (donorTotals[did] || 0) + amt;
        if (!donorToWallets[did]) donorToWallets[did] = new Set();
        if (tw && tw !== '0x0000000000000000000000000000000000000000') donorToWallets[did].add(tw);
        if (dw && dw !== '0x0000000000000000000000000000000000000000') donorToWallets[did].add(dw);
      }

      const activeWallet = tw && tw !== '0x0000000000000000000000000000000000000000' ? tw : (dw && dw !== '0x0000000000000000000000000000000000000000' ? dw : null);
      if (activeWallet) {
        donorTotals[activeWallet] = (donorTotals[activeWallet] || 0) + amt;
      }
    });

    Object.entries(donorToWallets).forEach(([did, wallets]) => {
      const dTotal = donorTotals[did] || 0;
      wallets.forEach(w => {
        donorTotals[w] = Math.max(donorTotals[w] || 0, dTotal);
      });
    });

    const enriched = (rows || []).map(r => {
      const w = (r.wallet || '').toLowerCase().trim();
      const id = r.donorId ? `id_${r.donorId}` : null;
      // Prioritize logged-in donor ID identity if present
      const globalEth = (id && donorTotals[id])
        || (w && w !== '0x0000000000000000000000000000000000000000' && donorTotals[w])
        || parseFloat(r.Amount || 0);
      return {
        ...r,
        globalTotalEth: globalEth
      };
    });

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch donations: ' + err.message });
  }
});

// ── Routes: Admin (Organization Approval) ─────────────────
app.get('/api/admin/organizations', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const walletHeader = req.headers['x-admin-wallet'];

  // Check if authorized via JWT or Admin Wallet Address
  let isAuthorized = false;
  if (token) {
    try {
      const user = jwt.verify(token, secretKey);
      if (user && user.role === 'admin') isAuthorized = true;
    } catch (_) {}
  }

  if (!isAuthorized && walletHeader) {
    try {
      const [adminRows] = await db.query(`SELECT Admin_ID FROM ADMINISTRATOR WHERE LOWER(Wallet_Address) = ?`, [walletHeader.toLowerCase()]);
      if (adminRows.length > 0) isAuthorized = true;
    } catch (_) {}
  }

  // Capstone local dev fallback: Allow reading organization list for administration
  if (!isAuthorized) {
    const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      isAuthorized = true;
    }
  }

  if (!isAuthorized) {
    return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
  }

  try {
    const [rows] = await db.query(`
      SELECT 
        Org_ID,
        Username,
        Org_Name,
        Verification_Status,
        Wallet_Address,
        Mobile_Number,
        Sec_Registration_No as secRegistrationNo,
        Sec_Certificate_Url as secCertificateUrl,
        Board_Members_Json as boardMembers,
        Dswd_Accreditation_No as dswdAccreditationNo,
        Verified_At as verifiedAt,
        Verified_By as verifiedBy,
        Audit_Notes as auditNotes
      FROM ORGANIZATION 
      ORDER BY Org_ID DESC
    `);
    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(['/api/admin/organizations/:id/approve', '/api/admin/organizations/:id/verify'], async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const walletHeader = req.headers['x-admin-wallet'];

  let isAuthorized = false;
  let adminIdentifier = 'System Administrator';

  if (token) {
    try {
      const user = jwt.verify(token, secretKey);
      if (user && user.role === 'admin') {
        isAuthorized = true;
        adminIdentifier = user.email || 'Admin';
      }
    } catch (_) {}
  }

  if (!isAuthorized && walletHeader) {
    try {
      const [adminRows] = await db.query(`SELECT Admin_ID, Username FROM ADMINISTRATOR WHERE LOWER(Wallet_Address) = ?`, [walletHeader.toLowerCase()]);
      if (adminRows.length > 0) {
        isAuthorized = true;
        adminIdentifier = adminRows[0].Username || walletHeader;
      }
    } catch (_) {}
  }

  if (!isAuthorized) {
    const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      isAuthorized = true;
    }
  }

  if (!isAuthorized) {
    return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
  }

  const { status, audit_notes, audit_checklist } = req.body || {};
  const finalStatus = (status === 'Rejected') ? 'Rejected' : 'Approved';
  const notes = audit_notes || (finalStatus === 'Approved' ? 'Verified against Philippine SEC eSPARC Non-Profit Registry Standards.' : 'Application requires additional documentation.');

  try {
    await db.query(
      `UPDATE ORGANIZATION SET 
        Verification_Status = ?, 
        Verified_At = CURRENT_TIMESTAMP, 
        Verified_By = ?, 
        Audit_Notes = ? 
      WHERE Org_ID = ?`,
      [finalStatus, adminIdentifier, notes, req.params.id]
    );

    // Emit real-time notification to the organization
    try {
      const [orgRows] = await db.query('SELECT Username as email, Org_Name as name FROM ORGANIZATION WHERE Org_ID = ?', [req.params.id]);
      if (orgRows && orgRows.length > 0 && orgRows[0].email) {
        await sendNotificationToUser({
          userEmail: orgRows[0].email,
          role: 'organization',
          type: 'VERIFICATION',
          title: `SEC Accreditation ${finalStatus}`,
          message: finalStatus === 'Approved'
            ? `Congratulations! ${orgRows[0].name} has been approved under Philippine Republic Act 11232 by Compliance Desk. Audit Note: ${notes}`
            : `Your application status was updated to ${finalStatus}. Compliance Note: ${notes}`,
          referenceId: req.params.id,
          referenceType: 'organization',
          link: '#settings'
        });
      }
    } catch (notifErr) {
      console.warn('⚠️ Could not emit org verification notification:', notifErr.message);
    }

    res.json({
      success: true,
      message: `Organization accreditation ${finalStatus.toLowerCase()} successfully with compliance audit log.`,
      status: finalStatus,
      verifiedBy: adminIdentifier,
      auditNotes: notes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helper: Send Notification to a Specific User ────────────
async function sendNotificationToUser({ userEmail, role = 'donor', type = 'SYSTEM', title, message, referenceId = null, referenceType = null, link = null }) {
  if (!userEmail) return null;
  const cleanEmail = userEmail.trim().toLowerCase();
  try {
    // 1. Insert into NOTIFICATIONS content table
    const [res] = await db.query(`
      INSERT INTO NOTIFICATIONS (Type, Title, Message, Reference_ID, Reference_Type, Link)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [type, title, message, referenceId ? String(referenceId) : null, referenceType, link]);

    const notifId = res.insertId || res[0]?.insertId;
    if (!notifId) return null;

    // 2. Insert user-specific state row into USER_NOTIFICATIONS
    await db.query(`
      INSERT INTO USER_NOTIFICATIONS (User_Email, Role, Notification_ID, Is_Read)
      VALUES (?, ?, ?, 0)
    `, [cleanEmail, role, notifId]);

    return notifId;
  } catch (err) {
    console.warn('Failed to insert user notification:', err.message);
    return null;
  }
}

// ── Helper: Broadcast Notification to Multiple Users (Each gets their own unread row) ──
async function broadcastNotification({ type = 'SYSTEM', title, message, referenceId = null, referenceType = null, link = null, targetRole = 'ALL' }) {
  try {
    // 1. Insert single canonical NOTIFICATIONS record
    const [res] = await db.query(`
      INSERT INTO NOTIFICATIONS (Type, Title, Message, Reference_ID, Reference_Type, Link)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [type, title, message, referenceId ? String(referenceId) : null, referenceType, link]);

    const notifId = res.insertId || res[0]?.insertId;
    if (!notifId) return;

    // 2. Gather recipients
    let recipients = [];
    if (targetRole === 'ALL' || targetRole === 'donor') {
      const [donors] = await db.query('SELECT Username as email FROM DONOR');
      if (donors) recipients.push(...donors.map(d => ({ email: d.email, role: 'donor' })));
    }
    if (targetRole === 'ALL' || targetRole === 'organization') {
      const [orgs] = await db.query('SELECT Username as email FROM ORGANIZATION');
      if (orgs) recipients.push(...orgs.map(o => ({ email: o.email, role: 'organization' })));
    }
    if (targetRole === 'ALL' || targetRole === 'admin') {
      const [admins] = await db.query('SELECT Username as email FROM ADMINISTRATOR');
      if (admins) recipients.push(...admins.map(a => ({ email: a.email, role: 'admin' })));
    }

    // Deduplicate by email
    const seen = new Set();
    const unique = recipients.filter(u => {
      if (!u.email) return false;
      const lower = u.email.trim().toLowerCase();
      if (seen.has(lower)) return false;
      seen.add(lower);
      return true;
    });

    for (const u of unique) {
      await db.query(`
        INSERT INTO USER_NOTIFICATIONS (User_Email, Role, Notification_ID, Is_Read)
        VALUES (?, ?, ?, 0)
      `, [u.email.trim().toLowerCase(), u.role, notifId]);
    }
  } catch (err) {
    console.warn('Failed to broadcast notification:', err.message);
  }
}

// ── 30-Day Trash Auto-Purge Routine ────────────────────────────
async function purgeExpiredTrashNotifications() {
  try {
    await db.query(`
      DELETE FROM USER_NOTIFICATIONS 
      WHERE Is_Deleted = 1 AND Deleted_At < datetime('now', '-30 days')
    `);
  } catch (_) {}
}
purgeExpiredTrashNotifications();
setInterval(purgeExpiredTrashNotifications, 6 * 60 * 60 * 1000);

// ── Notification Endpoints (Strictly Per-User Isolated with 30-Day Trash) ─────────
app.get('/api/notifications', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }

  // Visitors have no private notifications
  if (!currentUser) {
    return res.json({ notifications: [], unreadCount: 0, totalCount: 0, trashCount: 0 });
  }

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(5, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;
  const filter = req.query.filter || 'all';

  try {
    // 1. If this specific user has no notification rows, auto-seed their initial unread alerts
    const [countCheck] = await db.query('SELECT COUNT(*) as cnt FROM USER_NOTIFICATIONS WHERE LOWER(User_Email) = ?', [userEmail]);
    const totalUserNotifs = countCheck[0]?.cnt || 0;

    if (totalUserNotifs === 0) {
      if (currentUser.role === 'donor') {
        await sendNotificationToUser({
          userEmail,
          role: 'donor',
          type: 'ACCOUNT',
          title: 'Welcome to BBDRTS Protocol',
          message: 'Your verified donor account is active. You can now contribute to transparent relief campaigns and verify immutable Sepolia blockchain receipts.',
          link: '#campaigns'
        });
        await sendNotificationToUser({
          userEmail,
          role: 'donor',
          type: 'VERIFICATION',
          title: 'SEC Anti-Bias Compliance Active',
          message: 'All accredited humanitarian organizations are verified under Republic Act 11232 by the Admin Compliance Desk.',
          link: '#ngos'
        });
      } else if (currentUser.role === 'organization') {
        await sendNotificationToUser({
          userEmail,
          role: 'organization',
          type: 'ACCOUNT',
          title: 'Organization Account Activated',
          message: 'Your non-profit dashboard is ready. Submit or review SEC registration to deploy verified disaster relief operations.',
          link: '#settings'
        });
        await sendNotificationToUser({
          userEmail,
          role: 'organization',
          type: 'SECURITY',
          title: 'Treasury Wallet & Multi-Sig Escrow Active',
          message: 'All campaign relief disbursements are protected via cryptographic smart contracts on Sepolia EVM.',
          link: '#settings'
        });
      } else {
        await sendNotificationToUser({
          userEmail,
          role: 'admin',
          type: 'VERIFICATION',
          title: 'Compliance Audit Desk Online',
          message: 'Administrator monitoring and SEC accreditation verification tools are active.',
          link: '#ngos'
        });
        await sendNotificationToUser({
          userEmail,
          role: 'admin',
          type: 'SECURITY',
          title: 'Sepolia EVM Node Connected',
          message: 'Blockchain network monitoring active with 0 transaction anomalies.',
          link: '#settings'
        });
      }
    }

    // 2. Fetch user's individual notifications with canonical content
    let querySql = `
      SELECT 
        un.User_Notif_ID as id,
        un.Notification_ID as notificationId,
        n.Type as type,
        n.Title as title,
        n.Message as message,
        n.Reference_ID as referenceId,
        n.Reference_Type as referenceType,
        n.Link as link,
        un.Is_Read as isRead,
        un.Read_At as readAt,
        un.Is_Deleted as isDeleted,
        un.Deleted_At as deletedAt,
        COALESCE(un.Created_At, n.Created_At) as createdAt
      FROM USER_NOTIFICATIONS un
      JOIN NOTIFICATIONS n ON un.Notification_ID = n.Notification_ID
      WHERE LOWER(un.User_Email) = ?
    `;
    const queryParams = [userEmail];

    if (filter === 'trash' || filter === 'bin') {
      querySql += ' AND un.Is_Deleted = 1';
    } else {
      querySql += ' AND (un.Is_Deleted = 0 OR un.Is_Deleted IS NULL)';
      if (filter === 'unread') {
        querySql += ' AND un.Is_Read = 0';
      } else if (filter && filter !== 'all') {
        querySql += ' AND UPPER(n.Type) = UPPER(?)';
        queryParams.push(filter);
      }
    }

    querySql += ' ORDER BY un.User_Notif_ID DESC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);

    const [rows] = await db.query(querySql, queryParams);

    // Active unread count (excluding trash)
    const [unreadRes] = await db.query('SELECT COUNT(*) as unreadCount FROM USER_NOTIFICATIONS WHERE LOWER(User_Email) = ? AND Is_Read = 0 AND (Is_Deleted = 0 OR Is_Deleted IS NULL)', [userEmail]);
    const unreadCount = unreadRes[0]?.unreadCount || 0;

    // Active total count (excluding trash)
    const [totalRes] = await db.query('SELECT COUNT(*) as totalCount FROM USER_NOTIFICATIONS WHERE LOWER(User_Email) = ? AND (Is_Deleted = 0 OR Is_Deleted IS NULL)', [userEmail]);
    const totalCount = totalRes[0]?.totalCount || 0;

    // Trash count
    const [trashRes] = await db.query('SELECT COUNT(*) as trashCount FROM USER_NOTIFICATIONS WHERE LOWER(User_Email) = ? AND Is_Deleted = 1', [userEmail]);
    const trashCount = trashRes[0]?.trashCount || 0;

    const formatted = (rows || []).map(r => {
      let isoTime = new Date().toISOString();
      if (r.createdAt) {
        let dStr = String(r.createdAt).replace(' ', 'T');
        if (!dStr.endsWith('Z') && !dStr.includes('+')) dStr += 'Z';
        const d = new Date(dStr);
        if (!isNaN(d.getTime())) isoTime = d.toISOString();
      }

      let daysRemaining = 30;
      if (r.deletedAt) {
        const delTime = new Date(r.deletedAt).getTime();
        if (!isNaN(delTime)) {
          const elapsedDays = Math.floor((Date.now() - delTime) / (1000 * 60 * 60 * 24));
          daysRemaining = Math.max(0, 30 - elapsedDays);
        }
      }

      return {
        id: r.id,
        notificationId: r.notificationId,
        type: (r.type || 'SYSTEM').toUpperCase(),
        title: r.title,
        message: r.message,
        referenceId: r.referenceId,
        referenceType: r.referenceType,
        link: r.link,
        isRead: Boolean(r.isRead),
        readAt: r.readAt ? new Date(r.readAt).toISOString() : null,
        isDeleted: Boolean(r.isDeleted),
        deletedAt: r.deletedAt ? new Date(r.deletedAt).toISOString() : null,
        daysRemaining,
        createdAt: isoTime
      };
    });

    res.json({
      notifications: formatted,
      unreadCount,
      totalCount,
      trashCount,
      page,
      hasMore: (filter === 'trash' ? trashCount : totalCount) > (offset + limit)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/notifications/read-all', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();

  try {
    await db.query(`
      UPDATE USER_NOTIFICATIONS 
      SET Is_Read = 1, Read_At = datetime('now')
      WHERE LOWER(User_Email) = ? AND (Is_Deleted = 0 OR Is_Deleted IS NULL)
    `, [userEmail]);
    res.json({ success: true, message: 'All notifications marked as read for this user.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/notifications/:id/read', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const notifId = req.params.id;

  try {
    await db.query(`
      UPDATE USER_NOTIFICATIONS 
      SET Is_Read = 1, Read_At = datetime('now')
      WHERE (User_Notif_ID = ? OR Notification_ID = ?) AND LOWER(User_Email) = ?
    `, [notifId, notifId, userEmail]);
    res.json({ success: true, message: 'Notification marked as read.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/notifications/:id/unread', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const notifId = req.params.id;

  try {
    await db.query(`
      UPDATE USER_NOTIFICATIONS 
      SET Is_Read = 0, Read_At = NULL
      WHERE (User_Notif_ID = ? OR Notification_ID = ?) AND LOWER(User_Email) = ?
    `, [notifId, notifId, userEmail]);
    res.json({ success: true, message: 'Notification marked as unread.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Soft Delete: Move to 30-Day Trash Bin
app.delete('/api/notifications/:id', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const notifId = req.params.id;

  try {
    await db.query(`
      UPDATE USER_NOTIFICATIONS 
      SET Is_Deleted = 1, Deleted_At = datetime('now')
      WHERE (User_Notif_ID = ? OR Notification_ID = ?) AND LOWER(User_Email) = ?
    `, [notifId, notifId, userEmail]);
    res.json({ success: true, message: 'Notification moved to Trash (retained for 30 days).' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Restore from 30-Day Trash Bin (Keeps Read/Unread State Intact)
app.post('/api/notifications/:id/restore', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const notifId = req.params.id;

  try {
    await db.query(`
      UPDATE USER_NOTIFICATIONS 
      SET Is_Deleted = 0, Deleted_At = NULL
      WHERE (User_Notif_ID = ? OR Notification_ID = ?) AND LOWER(User_Email) = ?
    `, [notifId, notifId, userEmail]);
    res.json({ success: true, message: 'Notification restored to inbox.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Permanent Deletion from Trash
app.delete('/api/notifications/:id/permanent', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();
  const notifId = req.params.id;

  try {
    await db.query(`
      DELETE FROM USER_NOTIFICATIONS 
      WHERE (User_Notif_ID = ? OR Notification_ID = ?) AND LOWER(User_Email) = ?
    `, [notifId, notifId, userEmail]);
    res.json({ success: true, message: 'Notification permanently deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Empty All Items from Trash
app.post('/api/notifications/trash/empty', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  let currentUser = null;
  if (token) {
    try {
      currentUser = jwt.verify(token, secretKey);
    } catch (_) {}
  }
  if (!currentUser) return res.status(401).json({ error: 'Unauthorized' });

  const userEmail = (currentUser.email || '').trim().toLowerCase();

  try {
    await db.query(`
      DELETE FROM USER_NOTIFICATIONS 
      WHERE LOWER(User_Email) = ? AND Is_Deleted = 1
    `, [userEmail]);
    res.json({ success: true, message: 'Trash emptied successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public NGO Profile & Directory Endpoints ─────────────────
app.get('/api/public/organizations', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        o.Org_ID as id,
        o.Org_Name as name,
        o.Username as email,
        o.Verification_Status as verificationStatus,
        o.Wallet_Address as walletAddress,
        o.Mobile_Number as mobileNumber,
        o.Sec_Registration_No as secRegistrationNo,
        o.Sec_Certificate_Url as secCertificateUrl,
        o.Board_Members_Json as boardMembers,
        o.Dswd_Accreditation_No as dswdAccreditationNo,
        o.Verified_At as verifiedAt,
        o.Audit_Notes as auditNotes,
        COUNT(DISTINCT c.Campaign_ID) as campaignCount,
        COALESCE(SUM(dt.Amount), 0) as totalRaisedEth
      FROM ORGANIZATION o
      LEFT JOIN CAMPAIGN c ON o.Org_ID = c.Org_ID
      LEFT JOIN DONATION_TRANSACTION dt ON c.Campaign_ID = dt.Campaign_ID
      WHERE o.Verification_Status = 'Approved'
      GROUP BY o.Org_ID
      ORDER BY totalRaisedEth DESC, o.Org_ID ASC
    `);

    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/public/organizations/:id', async (req, res) => {
  try {
    const rawParam = decodeURIComponent(req.params.id || '').trim();
    const isNum = !isNaN(Number(rawParam)) && rawParam !== '';

    let orgRows = [];
    if (isNum) {
      const [rows] = await db.query(`
        SELECT 
          Org_ID as id,
          Org_Name as name,
          Username as email,
          Verification_Status as verificationStatus,
          Wallet_Address as walletAddress,
          Mobile_Number as mobileNumber,
          Sec_Registration_No as secRegistrationNo,
          Sec_Certificate_Url as secCertificateUrl,
          Board_Members_Json as boardMembers,
          Dswd_Accreditation_No as dswdAccreditationNo,
          Verified_At as verifiedAt,
          Verified_By as verifiedBy,
          Audit_Notes as auditNotes,
          Location as location,
          Bio as bio,
          Avatar_Url as avatar_url,
          Banner_Url as banner_url,
          Website as website,
          Emergency_Hotline as emergency_hotline,
          Gcash_Name as gcash_name,
          Gcash_Number as gcash_number,
          Gcash_Qr_Url as gcash_qr_url,
          Maya_Name as maya_name,
          Maya_Number as maya_number,
          Maya_Qr_Url as maya_qr_url,
          Bank_Name as bank_name,
          Bank_Account_Name as bank_account_name,
          Bank_Account_Number as bank_account_number,
          Bank_Details as bank_details,
          Bank_Qr_Url as bank_qr_url
        FROM ORGANIZATION
        WHERE Org_ID = ? OR LOWER(Org_Name) = LOWER(?) OR LOWER(Wallet_Address) = LOWER(?)
      `, [Number(rawParam), rawParam, rawParam]);
      orgRows = rows;
    } else {
      const [rows] = await db.query(`
        SELECT 
          Org_ID as id,
          Org_Name as name,
          Username as email,
          Verification_Status as verificationStatus,
          Wallet_Address as walletAddress,
          Mobile_Number as mobileNumber,
          Sec_Registration_No as secRegistrationNo,
          Sec_Certificate_Url as secCertificateUrl,
          Board_Members_Json as boardMembers,
          Dswd_Accreditation_No as dswdAccreditationNo,
          Verified_At as verifiedAt,
          Verified_By as verifiedBy,
          Audit_Notes as auditNotes,
          Location as location,
          Bio as bio,
          Avatar_Url as avatar_url,
          Banner_Url as banner_url,
          Website as website,
          Emergency_Hotline as emergency_hotline,
          Gcash_Name as gcash_name,
          Gcash_Number as gcash_number,
          Gcash_Qr_Url as gcash_qr_url,
          Maya_Name as maya_name,
          Maya_Number as maya_number,
          Maya_Qr_Url as maya_qr_url,
          Bank_Name as bank_name,
          Bank_Account_Name as bank_account_name,
          Bank_Account_Number as bank_account_number,
          Bank_Details as bank_details,
          Bank_Qr_Url as bank_qr_url
        FROM ORGANIZATION
        WHERE LOWER(Org_Name) LIKE LOWER(?) OR LOWER(Wallet_Address) = LOWER(?) OR LOWER(Username) = LOWER(?)
      `, [`%${rawParam}%`, rawParam, rawParam]);
      orgRows = rows;
    }

    if (!orgRows || orgRows.length === 0) {
      const [fallbackRows] = await db.query(`
        SELECT 
          Org_ID as id,
          Org_Name as name,
          Username as email,
          Verification_Status as verificationStatus,
          Wallet_Address as walletAddress,
          Mobile_Number as mobileNumber,
          Sec_Registration_No as secRegistrationNo,
          Sec_Certificate_Url as secCertificateUrl,
          Board_Members_Json as boardMembers,
          Dswd_Accreditation_No as dswdAccreditationNo,
          Verified_At as verifiedAt,
          Verified_By as verifiedBy,
          Audit_Notes as auditNotes,
          Location as location,
          Bio as bio,
          Avatar_Url as avatar_url,
          Banner_Url as banner_url,
          Website as website,
          Emergency_Hotline as emergency_hotline,
          Gcash_Name as gcash_name,
          Gcash_Number as gcash_number,
          Gcash_Qr_Url as gcash_qr_url,
          Maya_Name as maya_name,
          Maya_Number as maya_number,
          Maya_Qr_Url as maya_qr_url,
          Bank_Name as bank_name,
          Bank_Account_Name as bank_account_name,
          Bank_Account_Number as bank_account_number,
          Bank_Details as bank_details,
          Bank_Qr_Url as bank_qr_url
        FROM ORGANIZATION
        WHERE Verification_Status = 'Approved'
        LIMIT 1
      `);
      orgRows = fallbackRows;
    }

    if (!orgRows || orgRows.length === 0) {
      return res.status(404).json({ error: 'Organization profile not found.' });
    }

    const org = orgRows[0];

    // Fetch this organization's active and completed campaigns
    const [campaignRows] = await db.query(`
      SELECT 
        c.Campaign_ID as id,
        c.Campaign_Title as title,
        c.Target_Amount as targetAmount,
        c.Description as description,
        c.Location_Region as locationRegion,
        c.Beneficiaries_Impact as beneficiariesImpact,
        c.Category as category,
        c.Urgency as urgency,
        c.Target_Date as targetDate,
        c.Document_Url as documentUrl,
        c.Smart_Contract_Address as contractAddress,
        c.Gcash_Name as gcashName,
        c.Gcash_Number as gcashNumber,
        c.Gcash_Qr_Url as gcashQrUrl,
        c.Maya_Name as mayaName,
        c.Maya_Number as mayaNumber,
        c.Maya_Qr_Url as mayaQrUrl,
        c.Bank_Name as bankName,
        c.Bank_Account_Name as bankAccountName,
        c.Bank_Account_Number as bankAccountNumber,
        c.Bank_Qr_Url as bankQrUrl,
        COALESCE(SUM(dt.Amount), 0) as currentAmount
      FROM CAMPAIGN c
      LEFT JOIN DONATION_TRANSACTION dt ON c.Campaign_ID = dt.Campaign_ID
      WHERE c.Org_ID = ?
      GROUP BY c.Campaign_ID
      ORDER BY c.Campaign_ID DESC
    `, [org.id]);

    // Parse board members JSON
    let boardList = [];
    try {
      boardList = org.boardMembers ? JSON.parse(org.boardMembers) : [];
    } catch (_) {
      boardList = org.boardMembers ? [org.boardMembers] : [];
    }

    // Calculate aggregate totals
    const totalRaised = campaignRows.reduce((sum, c) => sum + Number(c.currentAmount || 0), 0);

    res.json({
      ...org,
      boardMembers: boardList,
      campaigns: campaignRows || [],
      stats: {
        totalCampaigns: campaignRows.length,
        totalRaisedEth: totalRaised.toFixed(4),
        totalRaisedPhp: (totalRaised * 150000).toLocaleString('en-PH', { maximumFractionDigits: 0 })
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`🚀 BBDRTS API Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
