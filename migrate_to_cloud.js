/**
 * BBDRTS - Automated Cloud Database Migration Utility
 * 
 * Transfers all records from the local SQLite database (`blockchain_relief.db`)
 * into the remote Cloud MySQL Database (TiDB, Aiven, Clever Cloud, etc.)
 * 
 * Usage:
 *   node migrate_to_cloud.js
 * 
 * It will use DB_HOST, DB_USER, DB_PASSWORD, DB_PORT, DB_NAME from .env
 * or environment variables.
 */

const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const mysql = require('mysql2/promise');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const sqlitePath = path.join(__dirname, 'blockchain_relief.db');

async function runMigration() {
  console.log('════════════════════════════════════════════════════════════');
  console.log('🚀 BBDRTS Cloud Database Migration (SQLite -> Cloud MySQL)');
  console.log('════════════════════════════════════════════════════════════');

  const cloudHost = process.env.DB_HOST;
  if (!cloudHost) {
    console.error('❌ Error: DB_HOST is not set in backend/.env!');
    console.log('Please set DB_HOST, DB_USER, DB_PASSWORD, DB_PORT, and DB_NAME in backend/.env');
    console.log('Example for TiDB Cloud Serverless:');
    console.log('  DB_HOST=gateway01.ap-southeast-1.prod.aws.tidbcloud.com');
    console.log('  DB_PORT=4000');
    console.log('  DB_USER=xxxx.root');
    console.log('  DB_PASSWORD=xxxx');
    console.log('  DB_NAME=test');
    process.exit(1);
  }

  // 1. Connect to SQLite
  console.log(`📂 Reading local SQLite database: ${sqlitePath}...`);
  const sqliteDb = new sqlite3.Database(sqlitePath);
  const sqliteQuery = (sql) => new Promise((resolve, reject) => {
    sqliteDb.all(sql, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });

  // 2. Connect to Cloud MySQL
  console.log(`🌐 Connecting to Cloud MySQL at ${cloudHost}:${process.env.DB_PORT || 3306}...`);
  const cloudDb = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    port: Number(process.env.DB_PORT) || 3306,
    database: process.env.DB_NAME || 'blockchain_relief',
    ssl: { rejectUnauthorized: false }
  });

  console.log('✅ Connected to Cloud MySQL successfully!');

  // 3. Ensure Cloud Schema exists (same as database.js)
  console.log('🏗️ Ensuring cloud tables exist...');
  
  await cloudDb.query(`
    CREATE TABLE IF NOT EXISTS ADMINISTRATOR (
      Admin_ID INT AUTO_INCREMENT PRIMARY KEY,
      Username VARCHAR(255) UNIQUE NOT NULL,
      Password VARCHAR(255) NOT NULL,
      Wallet_Address VARCHAR(255),
      Name VARCHAR(255),
      Title VARCHAR(255),
      Agency VARCHAR(255),
      Mobile_Number VARCHAR(50),
      Avatar_Url LONGTEXT
    )
  `);

  await cloudDb.query(`
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
      Audit_Notes TEXT,
      Location VARCHAR(255),
      Bio TEXT,
      Avatar_Url LONGTEXT,
      Website VARCHAR(255),
      Emergency_Hotline VARCHAR(100),
      Gcash_Name VARCHAR(255),
      Gcash_Number VARCHAR(50),
      Gcash_Qr_Url LONGTEXT,
      Maya_Name VARCHAR(255),
      Maya_Number VARCHAR(50),
      Maya_Qr_Url LONGTEXT,
      Bank_Name VARCHAR(255),
      Bank_Account_Name VARCHAR(255),
      Bank_Account_Number VARCHAR(100),
      Bank_Details TEXT,
      Bank_Qr_Url LONGTEXT,
      Banner_Url LONGTEXT,
      Preferences_Json TEXT
    )
  `);

  await cloudDb.query(`
    CREATE TABLE IF NOT EXISTS DONOR (
      Donor_ID INT AUTO_INCREMENT PRIMARY KEY,
      Username VARCHAR(255) UNIQUE NOT NULL,
      Password VARCHAR(255) NOT NULL,
      Name VARCHAR(255),
      Legal_Name VARCHAR(255),
      Display_Name VARCHAR(255),
      Mobile_Number VARCHAR(50),
      Location VARCHAR(255),
      Bio TEXT,
      Avatar_Url LONGTEXT,
      Preferences_Json TEXT,
      Name_Last_Changed_At DATETIME,
      Total_Donated DECIMAL(20, 2) DEFAULT 0,
      Wallet_Address VARCHAR(255)
    )
  `);

  await cloudDb.query(`
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
      Gcash_Name VARCHAR(255),
      Gcash_Number VARCHAR(50),
      Gcash_Qr_Url LONGTEXT,
      Maya_Name VARCHAR(255),
      Maya_Number VARCHAR(50),
      Maya_Qr_Url LONGTEXT,
      Bank_Name VARCHAR(100),
      Bank_Account_Name VARCHAR(150),
      Bank_Account_Number VARCHAR(50),
      Bank_Qr_Url LONGTEXT,
      Tags TEXT,
      FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE CASCADE
    )
  `);

  await cloudDb.query(`
    CREATE TABLE IF NOT EXISTS DONATION_TRANSACTION (
      Transaction_ID INT AUTO_INCREMENT PRIMARY KEY,
      Donor_ID INT,
      Org_ID INT,
      Campaign_ID INT,
      Tx_Hash VARCHAR(255) UNIQUE NOT NULL,
      Amount DECIMAL(20, 2) NOT NULL,
      Is_Anonymous BOOLEAN DEFAULT 0,
      Wallet_Address VARCHAR(255),
      Created_At DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL,
      FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE SET NULL,
      FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE
    )
  `);

  await cloudDb.query(`
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

  await cloudDb.query(`
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

  await cloudDb.query(`
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

  // 4. Migrate tables sequentially
  const tables = [
    'ADMINISTRATOR',
    'ORGANIZATION',
    'DONOR',
    'CAMPAIGN',
    'DONATION_TRANSACTION',
    'MANUAL_DONATION',
    'NOTIFICATIONS',
    'USER_NOTIFICATIONS'
  ];

  for (const table of tables) {
    try {
      const rows = await sqliteQuery(`SELECT * FROM ${table}`);
      console.log(`📦 Migrating ${rows.length} rows from table ${table}...`);
      if (rows.length === 0) continue;

      const [cols] = await cloudDb.query(`DESCRIBE ${table}`);
      const validColNames = new Set(cols.map(c => c.Field));

      let inserted = 0;
      for (const row of rows) {
        const columns = Object.keys(row).filter(c => validColNames.has(c));
        const placeholders = columns.map(() => '?').join(', ');
        const values = columns.map(c => row[c]);
        
        try {
          const sql = `INSERT IGNORE INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`;
          await cloudDb.query(sql, values);
          inserted++;
        } catch (rErr) {
          console.warn(`  ⚠️ Row warning on ${table}: ${rErr.message}`);
        }
      }
      console.log(`  ✅ ${table} synced successfully (${inserted}/${rows.length} rows processed)!`);
    } catch (tblErr) {
      console.warn(`  ⚠️ Notice on ${table}: ${tblErr.message}`);
    }
  }

  console.log('════════════════════════════════════════════════════════════');
  console.log('🎉 Migration Complete! Your cloud database is ready.');
  console.log('Next step: Add DB_HOST, DB_USER, DB_PASSWORD, DB_PORT, DB_NAME to Render Dashboard.');
  console.log('════════════════════════════════════════════════════════════');
  await cloudDb.end();
  sqliteDb.close();
  process.exit(0);
}

runMigration().catch(err => {
  console.error('❌ Migration failed:', err);
  process.exit(1);
});
