const mysql = require('mysql2/promise');
require('dotenv').config({ path: 'c:/Users/Gester/OneDrive/Desktop/Blockchain/backend/.env' });

async function check() {
  try {
    const db = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'blockchain_relief'
    });
    const [rows] = await db.query('DESCRIBE DONATION_TRANSACTION;');
    console.log(rows);
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
check();
