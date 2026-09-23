require('dotenv').config({ path: './.env' });
const mysql = require('mysql2/promise');

(async () => {
  try {
    const conn = await mysql.createConnection(process.env.DATABASE_URL || {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT || 4000,
      ssl: { rejectUnauthorized: false }
    });
    
    const [manual] = await conn.query('SELECT * FROM MANUAL_DONATION ORDER BY Manual_ID DESC LIMIT 10');
    console.log('RECENT MANUAL DONATIONS:');
    manual.forEach(m => {
      console.log(`ID: ${m.Manual_ID}, Donor: ${m.Donor_ID}, Campaign: ${m.Campaign_ID}, Amount: ${m.Amount}, Method: ${m.Payment_Method}, Status: ${m.Status}, Created: ${m.Created_At}`);
    });

    const [txs] = await conn.query('SELECT * FROM DONATION_TRANSACTION ORDER BY Transaction_ID DESC LIMIT 10');
    console.log('\nRECENT DONATION TRANSACTIONS:');
    txs.forEach(t => {
      console.log(`ID: ${t.Transaction_ID}, Donor: ${t.Donor_ID}, Org: ${t.Org_ID}, Campaign: ${t.Campaign_ID}, TxHash: ${t.Tx_Hash?.slice(0, 15)}..., Amount: ${t.Amount}, Method: ${t.Payment_Method}, Created: ${t.Created_At}`);
    });

    await conn.end();
  } catch (err) {
    console.error('Error:', err);
  }
})();
