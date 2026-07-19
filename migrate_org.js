const mysql = require('mysql2/promise');
require('dotenv').config({ path: 'c:/Users/Gester/OneDrive/Desktop/Blockchain/backend/.env' });

async function migrate() {
  try {
    const db = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'blockchain_relief'
    });
    
    // Add Org_ID foreign key
    await db.query(`
      ALTER TABLE DONATION_TRANSACTION 
      ADD COLUMN Org_ID INT DEFAULT NULL;
    `);
    
    await db.query(`
      ALTER TABLE DONATION_TRANSACTION
      ADD CONSTRAINT fk_dt_org
      FOREIGN KEY (Org_ID) REFERENCES ORGANIZATION(Org_ID) ON DELETE SET NULL;
    `);

    console.log('Successfully migrated DONATION_TRANSACTION to support Org donations!');
    process.exit(0);
  } catch (err) {
    if (err.code === 'ER_DUP_FIELDNAME') {
       console.log('Org_ID already exists. Skipping Migration.');
       process.exit(0);
    }
    console.error(err);
    process.exit(1);
  }
}
migrate();
