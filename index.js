const { Connection, clusterApiUrl } = require('@solana/web3.js');
const { Helius } = require('helius-sdk');

// Initialize Solana connection
const connection = new Connection(clusterApiUrl('mainnet-beta'));

// Initialize Helius SDK
const helius = new Helius({
  apiKey: 'a9a525af-f936-41d4-a5fa-e9c1da70ea11'
});

// Example function to fetch balance
async function getBalance(publicKey) {
  try {
    const balance = await connection.getBalance(publicKey);
    console.log(`Balance for ${publicKey}: ${balance} lamports`);
  } catch (error) {
    console.error('Error fetching balance:', error);
  }
}

// Example public key
const publicKey = 'FNr2c5oTt1k77BrnbHNFmKzGLjcM3eiyUoVxERkuqh9a';

// Fetch balance
getBalance(publicKey);
