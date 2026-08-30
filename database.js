const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const isCloud = !!process.env.DB_HOST;
let activeDriver = 'mysql'; // 'mysql' or 'sqlite'
let mysqlPool = null;
let sqliteDb = null;

// Dynamic MySQL configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  port: Number(process.env.DB_PORT) || 3306,
  database: isCloud ? (process.env.DB_NAME || 'defaultdb') : (process.env.DB_NAME || 'blockchain_relief'),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ...(isCloud ? { ssl: { rejectUnauthorized: false } } : {})
};

// ── Seed Default Accounts Helper ─────────────────────────────
async function seedDefaultAccounts(driver) {
  try {
    const adminPasswordHash = await bcrypt.hash('admin123', 10);
    const defaultPasswordHash = await bcrypt.hash('password123', 10);

    if (driver === 'sqlite') {
      sqliteDb.get('SELECT COUNT(*) as count FROM ADMINISTRATOR', (err, row) => {
        if (!err && row && row.count === 0) {
          sqliteDb.run(`INSERT INTO ADMINISTRATOR (Username, Password, Wallet_Address) VALUES (?, ?, ?)`,
            ['admin@bbdrts.gov.ph', adminPasswordHash, '0x206e5d8b76c8c4598d1a457493a746535560b771']);
        }
      });

      sqliteDb.get('SELECT COUNT(*) as count FROM DONOR', (err, row) => {
        if (!err && row && row.count === 0) {
          sqliteDb.run(`INSERT INTO DONOR (Username, Password, Total_Donated, Wallet_Address) VALUES (?, ?, ?, ?)`,
            ['donor@bbdrts.gov.ph', defaultPasswordHash, 0, null]);
        }
      });
    } else if (driver === 'mysql' && mysqlPool) {
      const [adminRows] = await mysqlPool.query('SELECT COUNT(*) as count FROM ADMINISTRATOR');
      if (adminRows[0].count === 0) {
        await mysqlPool.query(`INSERT INTO ADMINISTRATOR (Username, Password, Wallet_Address) VALUES (?, ?, ?)`,
          ['admin@bbdrts.gov.ph', adminPasswordHash, '0x206e5d8b76c8c4598d1a457493a746535560b771']);
      }

      const [donorRows] = await mysqlPool.query('SELECT COUNT(*) as count FROM DONOR');
      if (donorRows[0].count === 0) {
        await mysqlPool.query(`INSERT INTO DONOR (Username, Password, Total_Donated, Wallet_Address) VALUES (?, ?, ?, ?)`,
          ['donor@bbdrts.gov.ph', defaultPasswordHash, 0, null]);
      }
    }
  } catch (err) {
    console.warn('Seed account note:', err.message);
  }
}

// ── Initialize SQLite Fallback ────────────────────────────────
function initSqlite() {
  return new Promise((resolve, reject) => {
    const dbPath = path.resolve(__dirname, 'blockchain_relief.db');
    sqliteDb = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
      console.log('✅ Connected to local SQLite Database (Zero-Config Fallback).');

      // Create Tables in SQLite
      sqliteDb.serialize(() => {
        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS ADMINISTRATOR (
            Admin_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT UNIQUE NOT NULL,
            Password TEXT NOT NULL,
            Wallet_Address TEXT
          )
        `);

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS ORGANIZATION (
            Org_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT UNIQUE NOT NULL,
            Password TEXT NOT NULL,
            Org_Name TEXT,
            Verification_Status TEXT DEFAULT 'Pending',
            Wallet_Address TEXT,
            Mobile_Number TEXT,
            Sec_Registration_No TEXT,
            Sec_Certificate_Url TEXT,
            Board_Members_Json TEXT,
            Dswd_Accreditation_No TEXT,
            Verified_At DATETIME,
            Verified_By TEXT,
            Audit_Notes TEXT
          )
        `);

        // Migration check for existing SQLite databases
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Mobile_Number TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Sec_Registration_No TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Sec_Certificate_Url TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Board_Members_Json TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Dswd_Accreditation_No TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Verified_At DATETIME`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Verified_By TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE ORGANIZATION ADD COLUMN Audit_Notes TEXT`, () => {});

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS DONOR (
            Donor_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT UNIQUE NOT NULL,
            Password TEXT NOT NULL,
            Total_Donated REAL DEFAULT 0,
            Wallet_Address TEXT
          )
        `);

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS CAMPAIGN (
            Campaign_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Org_ID INTEGER,
            Campaign_Title TEXT NOT NULL,
            Target_Amount REAL NOT NULL,
            Smart_Contract_Address TEXT,
            Description TEXT,
            Location_Region TEXT,
            Gps_Coordinates TEXT,
            Beneficiaries_Impact TEXT,
            Allocations_Json TEXT,
            Contact_Info TEXT,
            Category TEXT,
            Urgency TEXT,
            Target_Date TEXT,
            Document_Url TEXT,
            Gcash_Number TEXT,
            Gcash_Qr_Url TEXT,
            Maya_Number TEXT,
            Maya_Qr_Url TEXT,
            Bank_Name TEXT,
            Bank_Account_Name TEXT,
            Bank_Account_Number TEXT,
            Bank_Qr_Url TEXT,
            FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE CASCADE
          )
        `);

        // Migration columns for existing SQLite database
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Description TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Location_Region TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Gps_Coordinates TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Beneficiaries_Impact TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Allocations_Json TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Contact_Info TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Category TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Urgency TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Target_Date TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Document_Url TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Gcash_Number TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Gcash_Qr_Url TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Maya_Number TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Maya_Qr_Url TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Name TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Account_Name TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Account_Number TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Qr_Url TEXT`, () => {});

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS DONATION_TRANSACTION (
            Transaction_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Donor_ID INTEGER,
            Org_ID INTEGER,
            Campaign_ID INTEGER,
            Tx_Hash TEXT UNIQUE NOT NULL,
            Amount REAL NOT NULL,
            Is_Anonymous INTEGER DEFAULT 0,
            Wallet_Address TEXT,
            Created_At DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL,
            FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE SET NULL,
            FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE
          )
        `);

        sqliteDb.run(`ALTER TABLE DONATION_TRANSACTION ADD COLUMN Wallet_Address TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE DONATION_TRANSACTION ADD COLUMN Created_At DATETIME DEFAULT CURRENT_TIMESTAMP`, () => {});

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS MANUAL_DONATION (
            Manual_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Donor_ID INTEGER,
            Campaign_ID INTEGER,
            Amount REAL NOT NULL,
            Payment_Method TEXT,
            Receipt_Base64 TEXT,
            Status TEXT DEFAULT 'Pending',
            Created_At DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL,
            FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE
          )
        `);

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS NOTIFICATIONS (
            Notification_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Type TEXT DEFAULT 'SYSTEM',
            Title TEXT NOT NULL,
            Message TEXT NOT NULL,
            Reference_ID TEXT,
            Reference_Type TEXT,
            Link TEXT,
            Created_At DATETIME DEFAULT CURRENT_TIMESTAMP
          )
        `);
        sqliteDb.run(`ALTER TABLE NOTIFICATIONS ADD COLUMN Reference_ID TEXT`, () => {});
        sqliteDb.run(`ALTER TABLE NOTIFICATIONS ADD COLUMN Reference_Type TEXT`, () => {});

        sqliteDb.run(`
          CREATE TABLE IF NOT EXISTS USER_NOTIFICATIONS (
            User_Notif_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            User_Email TEXT NOT NULL,
            Role TEXT NOT NULL,
            Notification_ID INTEGER NOT NULL,
            Is_Read INTEGER DEFAULT 0,
            Read_At DATETIME NULL,
            Is_Deleted INTEGER DEFAULT 0,
            Deleted_At DATETIME NULL,
            Created_At DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (Notification_ID) REFERENCES NOTIFICATIONS(Notification_ID) ON DELETE CASCADE
          )
        `, async (initErr) => {
          if (initErr) return reject(initErr);
          sqliteDb.run(`ALTER TABLE USER_NOTIFICATIONS ADD COLUMN Is_Deleted INTEGER DEFAULT 0`, () => {});
          sqliteDb.run(`ALTER TABLE USER_NOTIFICATIONS ADD COLUMN Deleted_At DATETIME NULL`, () => {});
          console.log('✅ ERD Tables Synchronized with SQLite.');
          await seedDefaultAccounts('sqlite');
          resolve();
        });
      });
    });
  });
}

// ── Dual Database Initialization ─────────────────────────────
async function initializeDatabase() {
  try {
    if (!isCloud) {
      try {
        const rootConn = await mysql.createConnection({
          host: dbConfig.host,
          user: dbConfig.user,
          password: dbConfig.password,
          port: dbConfig.port
        });
        await rootConn.query('CREATE DATABASE IF NOT EXISTS `blockchain_relief`');
        await rootConn.end();
      } catch (err) {
        // Silently skip if local MySQL port is closed
      }
    }

    mysqlPool = mysql.createPool(dbConfig);
    // Test connection with a quick ping
    await mysqlPool.query('SELECT 1');
    console.log('✅ Connected to MySQL Database.');

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS ADMINISTRATOR (
        Admin_ID INT AUTO_INCREMENT PRIMARY KEY,
        Username VARCHAR(255) UNIQUE NOT NULL,
        Password VARCHAR(255) NOT NULL,
        Wallet_Address VARCHAR(255)
      )
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS ORGANIZATION (
        Org_ID INT AUTO_INCREMENT PRIMARY KEY,
        Username VARCHAR(255) UNIQUE NOT NULL,
        Password VARCHAR(255) NOT NULL,
        Org_Name VARCHAR(255),
        Verification_Status VARCHAR(50) DEFAULT 'Pending',
        Wallet_Address VARCHAR(255),
        Mobile_Number VARCHAR(50),
        Sec_Registration_No VARCHAR(100),
        Sec_Certificate_Url LONGTEXT,
        Board_Members_Json TEXT,
        Dswd_Accreditation_No VARCHAR(100),
        Verified_At DATETIME,
        Verified_By VARCHAR(255),
        Audit_Notes TEXT
      )
    `);
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Mobile_Number VARCHAR(50)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Sec_Registration_No VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Sec_Certificate_Url LONGTEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Board_Members_Json TEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Dswd_Accreditation_No VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Verified_At DATETIME`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Verified_By VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE ORGANIZATION ADD COLUMN Audit_Notes TEXT`); } catch (_) {}

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS DONOR (
        Donor_ID INT AUTO_INCREMENT PRIMARY KEY,
        Username VARCHAR(255) UNIQUE NOT NULL,
        Password VARCHAR(255) NOT NULL,
        Total_Donated DECIMAL(20, 2) DEFAULT 0,
        Wallet_Address VARCHAR(255)
      )
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS CAMPAIGN (
        Campaign_ID INT AUTO_INCREMENT PRIMARY KEY,
        Org_ID INT,
        Campaign_Title VARCHAR(255) NOT NULL,
        Target_Amount DECIMAL(20, 2) NOT NULL,
        Smart_Contract_Address VARCHAR(255),
        Description TEXT,
        Location_Region VARCHAR(255),
        Gps_Coordinates VARCHAR(255),
        Beneficiaries_Impact VARCHAR(255),
        Allocations_Json TEXT,
        Contact_Info VARCHAR(255),
        Category VARCHAR(100),
        Urgency VARCHAR(100),
        Target_Date VARCHAR(100),
        Document_Url VARCHAR(500),
        Gcash_Number VARCHAR(50),
        Gcash_Qr_Url LONGTEXT,
        Maya_Number VARCHAR(50),
        Maya_Qr_Url LONGTEXT,
        Bank_Name VARCHAR(100),
        Bank_Account_Name VARCHAR(150),
        Bank_Account_Number VARCHAR(50),
        Bank_Qr_Url LONGTEXT,
        FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE CASCADE
      )
    `);
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Description TEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Location_Region VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Gps_Coordinates VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Beneficiaries_Impact VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Allocations_Json TEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Contact_Info VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Category VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Urgency VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Target_Date VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Document_Url VARCHAR(500)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Gcash_Number VARCHAR(50)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Gcash_Qr_Url LONGTEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Maya_Number VARCHAR(50)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Maya_Qr_Url LONGTEXT`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Name VARCHAR(100)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Account_Name VARCHAR(150)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Account_Number VARCHAR(50)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE CAMPAIGN ADD COLUMN Bank_Qr_Url LONGTEXT`); } catch (_) {}

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS DONATION_TRANSACTION (
        Transaction_ID INT AUTO_INCREMENT PRIMARY KEY,
        Donor_ID INT,
        Org_ID INT,
        Campaign_ID INT,
        Tx_Hash VARCHAR(255) UNIQUE NOT NULL,
        Amount DECIMAL(20, 2) NOT NULL,
        Is_Anonymous BOOLEAN DEFAULT 0,
        FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL,
        FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE SET NULL,
        FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE
      )
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS MANUAL_DONATION (
        Manual_ID INT AUTO_INCREMENT PRIMARY KEY,
        Donor_ID INT,
        Campaign_ID INT,
        Amount DECIMAL(20, 2) NOT NULL,
        Payment_Method VARCHAR(50),
        Receipt_Base64 LONGTEXT,
        Status VARCHAR(20) DEFAULT 'Pending',
        Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL,
        FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE
      )
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS NOTIFICATIONS (
        Notification_ID INT AUTO_INCREMENT PRIMARY KEY,
        Type VARCHAR(50) DEFAULT 'SYSTEM',
        Title VARCHAR(255) NOT NULL,
        Message TEXT NOT NULL,
        Reference_ID VARCHAR(255),
        Reference_Type VARCHAR(100),
        Link VARCHAR(255),
        Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    try { await mysqlPool.query(`ALTER TABLE NOTIFICATIONS ADD COLUMN Reference_ID VARCHAR(255)`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE NOTIFICATIONS ADD COLUMN Reference_Type VARCHAR(100)`); } catch (_) {}

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS USER_NOTIFICATIONS (
        User_Notif_ID INT AUTO_INCREMENT PRIMARY KEY,
        User_Email VARCHAR(255) NOT NULL,
        Role VARCHAR(50) NOT NULL,
        Notification_ID INT NOT NULL,
        Is_Read BOOLEAN DEFAULT 0,
        Read_At TIMESTAMP NULL,
        Is_Deleted BOOLEAN DEFAULT 0,
        Deleted_At TIMESTAMP NULL,
        Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (Notification_ID) REFERENCES NOTIFICATIONS(Notification_ID) ON DELETE CASCADE
      )
    `);

    try { await mysqlPool.query(`ALTER TABLE USER_NOTIFICATIONS ADD COLUMN Is_Deleted BOOLEAN DEFAULT 0`); } catch (_) {}
    try { await mysqlPool.query(`ALTER TABLE USER_NOTIFICATIONS ADD COLUMN Deleted_At TIMESTAMP NULL`); } catch (_) {}

    activeDriver = 'mysql';
    console.log('✅ ERD Tables Synchronized with MySQL.');
    await seedDefaultAccounts('mysql');
  } catch (error) {
    console.warn(`⚠️ MySQL unavailable (${error.code || error.message}). Activating SQLite3 fallback...`);
    activeDriver = 'sqlite';
    await initSqlite();
  }
}

// Start initialization immediately
const initPromise = initializeDatabase();

// Universal Query Helper compatible with both MySQL and SQLite
module.exports = {
  query: async (sql, params = []) => {
    await initPromise;

    if (activeDriver === 'mysql') {
      return mysqlPool.query(sql, params);
    }

    // SQLite mode
    return new Promise((resolve, reject) => {
      const trimmed = sql.trim();
      const isSelect = trimmed.toUpperCase().startsWith('SELECT');

      if (isSelect) {
        sqliteDb.all(sql, params, (err, rows) => {
          if (err) return reject(err);
          resolve([rows, []]);
        });
      } else {
        sqliteDb.run(sql, params, function (err) {
          if (err) return reject(err);
          resolve([{ insertId: this.lastID, affectedRows: this.changes }, []]);
        });
      }
    });
  }
};
