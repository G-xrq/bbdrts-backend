const mysql = require('mysql2/promise');

async function migrateData() {
  console.log('🔄 Starting Automatic Database Migration to Aiven...');
  try {
    // 1. Connect to Local Database
    console.log('🔌 Connecting to local XAMPP Database...');
    const localDb = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: '',
      database: 'blockchain_relief'
    });

    // 2. Extract Data
    console.log('📦 Reading local data...');
    const [admins] = await localDb.query('SELECT * FROM ADMINISTRATOR');
    const [orgs] = await localDb.query('SELECT * FROM ORGANIZATION');
    const [donors] = await localDb.query('SELECT * FROM DONOR');
    const [campaigns] = await localDb.query('SELECT * FROM CAMPAIGN');
    const [transactions] = await localDb.query('SELECT * FROM DONATION_TRANSACTION');
    console.log(`✅ Found: ${admins.length} Admins, ${orgs.length} NGOs, ${donors.length} Donors, ${campaigns.length} Campaigns, ${transactions.length} Transactions.`);

    // 3. Connect to Live Aiven Database
    console.log('🌐 Connecting to Live Aiven Database...');
    const remoteDb = await mysql.createConnection({
      host: 'mysql-13475406-capstone-v-2.e.aivencloud.com',
      user: 'avnadmin',
      password: 'REMOVED_FOR_GITHUB_SECURITY',
      port: 16261,
      database: 'defaultdb',
      ssl: { rejectUnauthorized: false } // Required for Aiven
    });
    console.log('✅ Connected to Aiven remotely!');

    // 4. Force Aiven to build the tables first
    console.log('🏗️ Building schema on Live Database...');
    await remoteDb.query(`CREATE TABLE IF NOT EXISTS ADMINISTRATOR (Admin_ID INT AUTO_INCREMENT PRIMARY KEY, Username VARCHAR(255) UNIQUE NOT NULL, Password VARCHAR(255) NOT NULL, Wallet_Address VARCHAR(255))`);
    await remoteDb.query(`CREATE TABLE IF NOT EXISTS ORGANIZATION (Org_ID INT AUTO_INCREMENT PRIMARY KEY, Username VARCHAR(255) UNIQUE NOT NULL, Password VARCHAR(255) NOT NULL, Verification_Status VARCHAR(50) DEFAULT 'Pending', Wallet_Address VARCHAR(255))`);
    await remoteDb.query(`CREATE TABLE IF NOT EXISTS DONOR (Donor_ID INT AUTO_INCREMENT PRIMARY KEY, Username VARCHAR(255) UNIQUE NOT NULL, Password VARCHAR(255) NOT NULL, Total_Donated DECIMAL(20,2) DEFAULT 0, Wallet_Address VARCHAR(255))`);
    await remoteDb.query(`CREATE TABLE IF NOT EXISTS CAMPAIGN (Campaign_ID INT AUTO_INCREMENT PRIMARY KEY, Org_ID INT, Campaign_Title VARCHAR(255) NOT NULL, Target_Amount DECIMAL(20,2) NOT NULL, Smart_Contract_Address VARCHAR(255), FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE CASCADE)`);
    await remoteDb.query(`CREATE TABLE IF NOT EXISTS DONATION_TRANSACTION (Transaction_ID INT AUTO_INCREMENT PRIMARY KEY, Donor_ID INT, Org_ID INT, Campaign_ID INT, Tx_Hash VARCHAR(255) UNIQUE NOT NULL, Amount DECIMAL(20,2) NOT NULL, Is_Anonymous BOOLEAN DEFAULT 0, FOREIGN KEY (Donor_ID) REFERENCES DONOR(Donor_ID) ON DELETE SET NULL, FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE SET NULL, FOREIGN KEY (Campaign_ID) REFERENCES CAMPAIGN(Campaign_ID) ON DELETE CASCADE)`);

    // 5. Inject Data into Live Cloud!
    console.log('🚀 Pushing data to the Cloud...');
    
    // Admins
    for(let a of admins) {
      await remoteDb.query(`INSERT IGNORE INTO ADMINISTRATOR (Admin_ID, Username, Password, Wallet_Address) VALUES (?, ?, ?, ?)`, [a.Admin_ID, a.Username, a.Password, a.Wallet_Address]);
    }
    // Orgs
    for(let o of orgs) {
      await remoteDb.query(`INSERT IGNORE INTO ORGANIZATION (Org_ID, Username, Password, Verification_Status, Wallet_Address) VALUES (?, ?, ?, ?, ?)`, [o.Org_ID, o.Username, o.Password, o.Verification_Status, o.Wallet_Address]);
    }
    // Donors
    for(let d of donors) {
      await remoteDb.query(`INSERT IGNORE INTO DONOR (Donor_ID, Username, Password, Total_Donated, Wallet_Address) VALUES (?, ?, ?, ?, ?)`, [d.Donor_ID, d.Username, d.Password, d.Total_Donated, d.Wallet_Address]);
    }
    // Campaigns
    for(let c of campaigns) {
      await remoteDb.query(`INSERT IGNORE INTO CAMPAIGN (Campaign_ID, Org_ID, Campaign_Title, Target_Amount, Smart_Contract_Address) VALUES (?, ?, ?, ?, ?)`, [c.Campaign_ID, c.Org_ID, c.Campaign_Title, c.Target_Amount, c.Smart_Contract_Address]);
    }
    // Transactions
    for(let t of transactions) {
      await remoteDb.query(`INSERT IGNORE INTO DONATION_TRANSACTION (Transaction_ID, Donor_ID, Org_ID, Campaign_ID, Tx_Hash, Amount, Is_Anonymous) VALUES (?, ?, ?, ?, ?, ?, ?)`, [t.Transaction_ID, t.Donor_ID, t.Org_ID, t.Campaign_ID, t.Tx_Hash, t.Amount, t.Is_Anonymous]);
    }

    console.log('🎉 100% COMPLETE! Your Live Aiven Database now mirrors your local XAMPP database!');
    process.exit(0);

  } catch (error) {
    console.error('❌ MIGRATION FAILED:', error);
    process.exit(1);
  }
}

migrateData();
