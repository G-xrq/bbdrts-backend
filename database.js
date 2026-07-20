const mysql = require('mysql2/promise');

const isCloud = !!process.env.DB_HOST;

// Dynamic MySQL configuration (Cloud + Localhost Fallback)
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  port: process.env.DB_PORT || 3306,
  ...(isCloud ? { ssl: { rejectUnauthorized: false } } : {})
};

let mysqlPool = null;

async function initializeDatabase() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Aiven strict permissions reject CREATE DATABASE, so we only initialize it locally.
    if (!isCloud) {
       await connection.query('CREATE DATABASE IF NOT EXISTS `blockchain_relief`');
    }
    
    await connection.end();

    mysqlPool = mysql.createPool({
      ...dbConfig,
      database: process.env.DB_NAME || 'blockchain_relief',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });

    console.log('✅ Connected to MySQL Database (blockchain_relief).');

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
        Verification_Status VARCHAR(50) DEFAULT 'Pending',
        Wallet_Address VARCHAR(255)
      )
    `);

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
        FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE CASCADE
      )
    `);

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

    console.log('✅ ERD Tables Synchronized with MySQL.');
  } catch (error) {
    console.error('❌ Error initializing MySQL Database:', error);
  }
}

// Start initialization immediately
const initPromise = initializeDatabase();

module.exports = {
  query: async (sql, params) => {
    await initPromise; 
    return mysqlPool.query(sql, params);
  }
};
