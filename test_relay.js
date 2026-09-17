require('dotenv').config();
const { relayDonation, getRelayerStatus } = require('./services/blockchainRelayer');

async function test() {
  console.log('1. Checking Relayer Status:');
  const status = await getRelayerStatus();
  console.log(status);

  console.log('\n2. Testing Relayer for Campaign #1 (Blood Donation):');
  const res = await relayDonation({
    campaignId: 1,
    amountPhp: 500,
    amountEth: 500 / 170000,
    paymentMethod: 'GCASH',
    referenceNumber: 'TEST-RELAY-' + Date.now(),
    donorWallet: null,
    donorId: 9999
  });
  console.log('Relay Result:', res);
}
test().catch(console.error);
