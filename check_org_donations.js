require('dotenv').config();
const db = require('./database');
(async () => {
  try {
    const userId = 3;
    const sql = `SELECT dt.Transaction_ID as id, dt.Tx_Hash as txHash, dt.Amount as amount, COALESCE(dt.Payment_Method, 'ETH') as paymentMethod, dt.Campaign_ID as campaignId, c.Campaign_Title as campaignTitle, o.Org_Name as orgName FROM DONATION_TRANSACTION dt LEFT JOIN DONOR d ON dt.Donor_ID = d.Donor_ID LEFT JOIN CAMPAIGN c ON dt.Campaign_ID = c.Campaign_ID LEFT JOIN ORGANIZATION o ON (dt.Org_ID = o.Org_ID OR c.Org_ID = o.Org_ID) WHERE (dt.Org_ID = ? OR c.Org_ID = ?) ORDER BY dt.Transaction_ID DESC`;
    const [rows] = await db.query(sql, [userId, userId]);
    console.log('Found rows for Org 3:', rows.length);
    console.log(rows.slice(0, 5));

    // Also check pending
    const [pending] = await db.query(`
      SELECT m.*, d.Username as Donor_Name, c.Campaign_Title 
      FROM MANUAL_DONATION m 
      LEFT JOIN DONOR d ON m.Donor_ID = d.Donor_ID 
      JOIN CAMPAIGN c ON m.Campaign_ID = c.Campaign_ID 
      WHERE m.Status = 'Pending' AND c.Org_ID = ?
    `, [userId]);
    console.log('Pending for Org 3:', pending.length);
    console.log(pending);
  } catch (e) {
    console.error(e);
  }
  process.exit();
})();
