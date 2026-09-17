require('dotenv').config();
const { ethers } = require('ethers');
const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com');
const contractAddr = process.env.SMART_CONTRACT_ADDRESS || '0xB8Effb4f0394946a01da9C5342fC2e70c1E99ddA';
const abi = [
  'function owner() view returns (address)',
  'function campaignCount() view returns (uint256)',
  'function campaigns(uint256) view returns (address payable orgAddress, string memory title, uint256 targetAmount, uint256 currentAmount, bool isActive)'
];
async function check() {
  const contract = new ethers.Contract(contractAddr, abi, provider);
  const owner = await contract.owner();
  const count = await contract.campaignCount();
  console.log('Contract:', contractAddr);
  console.log('Owner:', owner);
  console.log('CampaignCount:', count.toString());
  for (let i = 1; i <= Number(count); i++) {
    try {
      const c = await contract.campaigns(i);
      console.log(`Campaign #${i}: "${c.title}" | Target: ${ethers.formatEther(c.targetAmount)} ETH | Raised: ${ethers.formatEther(c.currentAmount)} ETH | Active: ${c.isActive} | Org: ${c.orgAddress}`);
    } catch(err) {
      console.log(`Campaign #${i} error:`, err.message);
    }
  }
}
check().catch(console.error);
