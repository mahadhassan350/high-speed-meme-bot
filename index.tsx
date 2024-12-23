require('dotenv').config();
const {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    ComputeBudgetProgram
} = require('@solana/web3.js');
const { JitoRpcClient } = require('@jito-foundation/sdk');
const TelegramBot = require('node-telegram-bot-api');
const WebSocket = require('ws');
const Big = require('big.js');
const { default: axios } = require('axios');

const CONFIG = {
    rpc: {
        helius: {
            http: process.env.HELIUS_HTTP_URL,
            ws: process.env.HELIUS_WS_URL,
            eclipse: process.env.HELIUS_ECLIPSE_URL
        },
        jito: {
            blockEngine: process.env.JITO_BLOCK_ENGINE_URL,
            relayer: process.env.JITO_RELAYER_URL,
            ntp: process.env.JITO_NTP_URL
        }
    },
    wallet: {
        main: {
            address: process.env.WALLET_ADDRESS,
            privateKey: process.env.WALLET_PRIVATE_KEY
        },
        target: process.env.TARGET_WALLET
    },
    trading: {
        maxExposurePerTrade: 1.0,
        stopLossPercentage: 20,
        maxDailyLoss: 1.0,
        minLiquidity: 50,
        maxSlippage: 1.5,
        gasMultiplier: 1.2,
        frontrunDelay: 50,
        copySizePercentage: 90,
        maxRetries: 3,
        requestTimeout: 5000
    },
    monitoring: {
        discordWebhook: process.env.DISCORD_WEBHOOK,
        telegram: {
            token: process.env.TELEGRAM_BOT_TOKEN,
            channelId: '@alphabeforealpha'
        },
        alertThresholds: {
            failedTrades: 3,
            maxExecutionTime: 1000,
            minProfitThreshold: -0.1
        }
    }
};

class RateLimiter {
    constructor(limit, interval) {
        this.limit = limit;
        this.interval = interval;
        this.requests = [];
    }

    tryAcquire() {
        const now = Date.now();
        this.requests = this.requests.filter(time => now - time < this.interval);
        if (this.requests.length >= this.limit) return false;
        this.requests.push(now);
        return true;
    }
}

class AlertManager {
    constructor(config) {
        this.config = config;
        this.telegramBot = new TelegramBot(config.monitoring.telegram.token, {polling: false});
    }

    async sendAlert(message) {
        try {
            await this.telegramBot.sendMessage(
                this.config.monitoring.telegram.channelId,
                `🤖 Meme Bot Alert:\n${message}`
            );

            if (this.config.monitoring.discordWebhook) {
                await axios.post(this.config.monitoring.discordWebhook, {
                    content: `[${new Date().toISOString()}] ${message}`,
                    username: 'Meme Bot Alert'
                });
            }
        } catch (error) {
            console.error('Alert sending failed:', error);
        }
    }
}

class TokenValidator {
    constructor() {
        this.blacklist = new Set();
        this.suspiciousPatterns = [
            /^test/i,
            /honeypot/i,
            /^scam/i,
            /presale/i,
            /^dev/i
        ];
        this.validationCache = new Map();
    }

    async validateToken(mint, connection) {
        if (this.blacklist.has(mint)) return false;
        
        const cached = this.validationCache.get(mint);
        if (cached && Date.now() - cached.timestamp < 60000) {
            return cached.isValid;
        }

        try {
            const [metadata, supply] = await Promise.all([
                connection.getParsedAccountInfo(new PublicKey(mint)),
                connection.getTokenSupply(new PublicKey(mint))
            ]);

            const isValid = this.checkTokenMetrics(metadata.value?.data, supply);
            this.validationCache.set(mint, {
                isValid,
                timestamp: Date.now()
            });

            return isValid;
        } catch (error) {
            console.error('Token validation error:', error);
            return false;
        }
    }

    checkTokenMetrics(metadata, supply) {
        if (!metadata || !supply) return false;
        
        const risks = [
            supply.value.uiAmount > 1e15,
            this.suspiciousPatterns.some(pattern => pattern.test(metadata.name)),
            metadata.holders < 10,
            metadata.createdAt > Date.now() - (24 * 60 * 60 * 1000),
            !metadata.verified
        ];
        
        return !risks.some(risk => risk);
    }
}

class InstructionDecoder {
    decode(data) {
        const view = new DataView(data.buffer);
        return {
            instruction: view.getUint8(0),
            amount: view.getBigUint64(1, true),
            flags: view.getUint8(9),
            padding: view.getUint16(10, true),
            additionalData: this.parseAdditionalData(view, 12)
        };
    }

    encode(decoded) {
        const buffer = new ArrayBuffer(decoded.size || 64);
        const view = new DataView(buffer);
        
        view.setUint8(0, decoded.instruction);
        view.setBigUint64(1, decoded.amount, true);
        view.setUint8(9, decoded.flags || 0);
        view.setUint16(10, decoded.padding || 0, true);
        
        if (decoded.additionalData) {
            this.writeAdditionalData(view, 12, decoded.additionalData);
        }
        
        return Buffer.from(buffer);
    }

    parseAdditionalData(view, offset) {
        const length = view.getUint8(offset);
        const data = {};
        
        let currentOffset = offset + 1;
        for (let i = 0; i < length; i++) {
            const fieldType = view.getUint8(currentOffset);
            const fieldLength = view.getUint8(currentOffset + 1);
            const fieldData = new Uint8Array(
                view.buffer.slice(currentOffset + 2, currentOffset + 2 + fieldLength)
            );
            
            data[fieldType] = fieldData;
            currentOffset += 2 + fieldLength;
        }
        
        return data;
    }

    writeAdditionalData(view, offset, data) {
        const fields = Object.entries(data);
        view.setUint8(offset, fields.length);
        
        let currentOffset = offset + 1;
        for (const [type, value] of fields) {
            view.setUint8(currentOffset, parseInt(type));
            view.setUint8(currentOffset + 1, value.length);
            
            const valueArray = new Uint8Array(value);
            for (let i = 0; i < valueArray.length; i++) {
                view.setUint8(currentOffset + 2 + i, valueArray[i]);
            }
            
            currentOffset += 2 + value.length;
        }
    }
}

class RiskManager {
    constructor() {
        this.dailyPnL = 0;
        this.trades = [];
        this.startTime = Date.now();
        this.positionSizes = new Map();
    }

    async validateTrade(amount, price) {
        if (amount > CONFIG.trading.maxExposurePerTrade) {
            throw new Error('Trade exceeds max exposure');
        }
        
        if (this.dailyPnL <= -CONFIG.trading.maxDailyLoss) {
            throw new Error('Daily loss limit reached');
        }

        return true;
    }

    calculatePositionSize(targetSize) {
        return targetSize * (CONFIG.trading.copySizePercentage / 100);
    }

    updatePnL(profit, token) {
        this.dailyPnL += profit;
        this.trades.push({
            timestamp: Date.now(),
            profit,
            token
        });
    }

    getTokenPosition(token) {
        return this.positionSizes.get(token) || 0;
    }

    updatePosition(token, size) {
        this.positionSizes.set(token, (this.positionSizes.get(token) || 0) + size);
    }

    resetDaily() {
        if (Date.now() - this.startTime >= 24 * 60 * 60 * 1000) {
            this.dailyPnL = 0;
            this.trades = [];
            this.startTime = Date.now();
            this.positionSizes.clear();
        }
    }
}

class WebSocketManager {
    constructor(url, handler, maxRetries = 3) {
        this.url = url;
        this.handler = handler;
        this.maxRetries = maxRetries;
        this.retryCount = 0;
        this.ws = null;
        this.rateLimiter = new RateLimiter(100, 60000);
        this.setupConnection();
    }

    setupConnection() {
        this.ws = new WebSocket(this.url);
        
        this.ws.on('message', async (data) => {
            if (!this.rateLimiter.tryAcquire()) {
                console.warn('WebSocket rate limit exceeded');
                return;
            }

            try {
                const message = JSON.parse(data);
                await this.handler(message);
            } catch (error) {
                this.handleError(error);
            }
        });

        this.ws.on('error', this.handleError.bind(this));
        this.ws.on('close', this.handleClose.bind(this));
    }

    handleError(error) {
        console.error('WebSocket error:', error);
        if (this.retryCount < this.maxRetries) {
            setTimeout(() => this.reconnect(), Math.pow(2, this.retryCount) * 1000);
            this.retryCount++;
        }
    }

    handleClose() {
        if (this.retryCount < this.maxRetries) {
            this.reconnect();
        }
    }

    reconnect() {
        if (this.ws) {
            this.ws.terminate();
        }
        this.setupConnection();
    }

    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

class HighSpeedMemeBot {
    constructor() {
        this.initializeConnections();
        this.wallet = Keypair.fromSecretKey(Buffer.from(CONFIG.wallet.main.privateKey, 'base64'));
        this.targetWallet = new PublicKey(CONFIG.wallet.target);
        this.pendingTxs = new Map();
        this.riskManager = new RiskManager();
        this.tokenValidator = new TokenValidator();
        this.decoder = new InstructionDecoder();
        this.alertManager = new AlertManager(CONFIG);
        this.lastGasOptimization = 0;
        this.metrics = {
            totalTrades: 0,
            successfulTrades: 0,
            failedTrades: 0,
            totalProfit: 0,
            executionTimes: []
        };
        this.circuitBreaker = {
            enabled: false,
            failedTrades: 0,
            lastReset: Date.now()
        };
    }

    initializeConnections() {
        this.heliusConnection = new Connection(CONFIG.rpc.helius.http, {
            commitment: 'processed',
            confirmTransactionInitialTimeout: CONFIG.trading.requestTimeout
        });
        this.jitoClient = new JitoRpcClient(CONFIG.rpc.jito.blockEngine);
        this.wsManager = new WebSocketManager(
            CONFIG.rpc.helius.ws,
            this.handleTargetActivity.bind(this)
        );
    }

    async optimizeGasFee() {
        if (Date.now() - this.lastGasOptimization < 1000) {
            return this.lastGasPrice;
        }

        try {
            const recentFees = await this.jitoClient.getRecentPrioritizationFees();
            const optimalFee = Math.max(...recentFees.map(f => f.prioritizationFee)) * CONFIG.trading.gasMultiplier;
            this.lastGasPrice = optimalFee;
            this.lastGasOptimization = Date.now();
            return optimalFee;
        } catch (error) {
            console.error('Gas optimization error:', error);
            return this.lastGasPrice || 1_000_000;
        }
    }

    async createCopyTrade(tradeDetails) {
        const tx = new Transaction();
        
        const gasFee = await this.optimizeGasFee();
        tx.add(ComputeBudgetProgram.setComputeUnitPrice({
            microLamports: gasFee
        }));
        
        const positionSize = this.riskManager.calculatePositionSize(tradeDetails.amount);
        
        for (const ix of tradeDetails.route) {
            const modifiedIx = this.modifyInstructionForBot(ix, positionSize);
            tx.add(modifiedIx);
        }

        return tx;
    }

    modifyInstructionForBot(ix, size) {
        const accounts = ix.accounts.map(acc => 
            acc.equals(this.targetWallet) ? this.wallet.publicKey : acc
        );
        
        let data = ix.data;
        if (this.isAmountField(ix)) {
            const decoded = this.decoder.decode(data);
            decoded.amount = BigInt(Math.floor(Number(decoded.amount) * size));
            data = this.decoder.encode(decoded);
        }
        
        return {
            ...ix,
            accounts,
            data
        };
    }

    isAmountField(ix) {
        return ix.data.length >= 9 && ix.data[0] === 0x01;
    }

    async handleTargetActivity(activity) {
        try {
            if (this.circuitBreaker.enabled) return;
            if (!this.isRelevantActivity(activity)) return;

            const tradeDetails = await this.analyzeTargetTrade(activity);
            const tokenValid = await this.tokenValidator.validateToken(
                tradeDetails.token,
                this.heliusConnection
            );
            if (!tokenValid) return;

            const tx = await this.createCopyTrade(tradeDetails);
            if (!tx) return;

            const simulationResult = await this.heliusConnection.simulateTransaction(tx);
            if (!this.validateSimulation(simulationResult, tradeDetails.expectedProfit)) return;

            await this.riskManager.validateTrade(tradeDetails.amount, tradeDetails.price);
            
            const startTime = Date.now();
            const signature = await this.sendViaJito(tx);
            const executionTime = Date.now() - startTime;
            
            await this.monitorTransaction(signature, tradeDetails);
            this.updateMetrics({
                success: true,
                executionTime,
                profit: tradeDetails.expectedProfit
            });
        } catch (error) {
            console.error('Error handling target activity:', error);
            this.updateMetrics({ success: false });
            this.circuitBreaker.failedTrades++;
            
            if (this.circuitBreaker.failedTrades >= CONFIG.monitoring.alertThresholds.failedTrades) {
                this.circuitBreaker.enabled = true;
                await this.alertManager.sendAlert('Circuit breaker triggered due to multiple failed trades');
            }
        }
    }

    async validateSimulation(simulation, expectedProfit) {
        if (simulation.value.err) return false;
        
        const preBalances = simulation.value.accounts.map(a => new Big(a.lamports));
        const postBalances = simulation.value.accounts.map(a => new Big(a.lamports));
        
        const profitLoss = postBalances.reduce((acc, bal, i) => 
            acc.plus(bal.minus(preBalances[i])), new Big(0));
        
        return profitLoss.gte(new Big(expectedProfit).times(0.98));
    }

    async sendViaJito(transaction) {
        try {
            transaction.sign(this.wallet);
            
            const signature = await this.jitoClient.sendTransaction(transaction, {
                skipPreflight: true,
                maxRetries: 1,
            });
            
            this.pendingTxs.set(signature, {
                tx: transaction,
                timestamp: Date.now()
            });
            
            return signature;
        } catch (error) {
            console.error('Failed to send transaction:', error);
            throw error;
        }
    }

    async monitorTransaction(signature, tradeDetails) {
        try {
            const confirmation = await this.heliusConnection.confirmTransaction(signature);
            if (confirmation.value.err) {
                throw new Error('Transaction failed');
            }

            this.riskManager.updatePosition(tradeDetails.token, tradeDetails.amount);
            await this.alertManager.sendAlert(`Trade successful: ${signature}`);
        } catch (error) {
            console.error('Transaction monitoring error:', error);
            await this.alertManager.sendAlert(`Transaction failed: ${signature}`);
        }
    }

    async emergencyExit() {
        try {
            console.log('Initiating emergency exit...');
            
            const openPositions = Array.from(this.riskManager.positionSizes.entries());
            for (const [token, size] of openPositions) {
                if (size > 0) {
                    await this.closePosition(token, size);
                }
            }

            for (const [signature] of this.pendingTxs) {
                try {
                    await this.heliusConnection.cancelTransaction(signature);
                } catch (error) {
                    console.error(`Failed to cancel transaction ${signature}:`, error);
                }
            }

            await this.alertManager.sendAlert('Emergency exit completed');
            return true;
        } catch (error) {
            console.error('Emergency exit failed:', error);
            await this.alertManager.sendAlert(`Emergency exit failed: ${error.message}`);
            return false;
        }
    }

    async closePosition(token, size) {
        try {
            const market = await this.findBestMarket(token);
            if (!market) {
                throw new Error(`No market found for token ${token}`);
            }

            const tx = await this.createClosePositionTx(market, token, size);
            const signature = await this.sendViaJito(tx);
            await this.heliusConnection.confirmTransaction(signature);
        } catch (error) {
            console.error(`Failed to close position for ${token}:`, error);
        }
    }

    async findBestMarket(token) {
        const KNOWN_DEX_PROGRAMS = [
            'srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX', // Serum
            '9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP', // Raydium
            'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc'  // Orca
        ];

        for (const programId of KNOWN_DEX_PROGRAMS) {
            try {
                const markets = await this.heliusConnection.getProgramAccounts(
                    new PublicKey(programId),
                    {
                        filters: [
                            {
                                memcmp: {
                                    offset: 5,
                                    bytes: token
                                }
                            }
                        ]
                    }
                );

                if (markets.length > 0) {
                    return {
                        programId: new PublicKey(programId),
                        address: markets[0].pubkey
                    };
                }
            } catch (error) {
                console.error(`Error finding market for ${programId}:`, error);
            }
        }
        return null;
    }

    async createClosePositionTx(market, token, size) {
        const tx = new Transaction();
        const gasFee = await this.optimizeGasFee();
        
        tx.add(ComputeBudgetProgram.setComputeUnitPrice({
            microLamports: gasFee
        }));

        // Add market-specific close position instruction
        const closeIx = await this.createCloseInstruction(market, token, size);
        tx.add(closeIx);

        return tx;
    }

    async createCloseInstruction(market, token, size) {
        // Implement market-specific close instruction creation
        // This would vary based on the DEX being used
        return null;
    }

    updateMetrics({ success, executionTime, profit }) {
        this.metrics.totalTrades++;
        if (success) {
            this.metrics.successfulTrades++;
            this.metrics.totalProfit += profit || 0;
        } else {
            this.metrics.failedTrades++;
        }
        if (executionTime) {
            this.metrics.executionTimes.push(executionTime);
        }
    }

    async start() {
        console.log('Starting bot...');
        await this.wsManager.setupConnection();
        
        this.intervals = [
            setInterval(() => this.riskManager.resetDaily(), 60000),
            setInterval(() => this.checkConnections(), 30000),
            setInterval(() => this.monitorPerformance(), 300000),
            setInterval(() => this.resetCircuitBreaker(), 3600000)
        ];

        await this.alertManager.sendAlert('Bot started successfully');
    }

    async stop() {
        this.wsManager.close();
        this.intervals?.forEach(clearInterval);
        await this.alertManager.sendAlert('Bot stopped safely');
        console.log('Bot stopped safely');
    }
}

// Error handling
process.on('uncaughtException', async (error) => {
    console.error('Uncaught exception:', error);
    const bot = new HighSpeedMemeBot();
    await bot.emergencyExit();
});

process.on('SIGINT', async () => {
    console.log('Shutting down...');
    const bot = new HighSpeedMemeBot();
    await bot.stop();
    process.exit(0);
});

// Start the bot
const bot = new HighSpeedMemeBot();
bot.start().catch(console.error);

module.exports = {
    HighSpeedMemeBot,
    RiskManager,
    TokenValidator,
    AlertManager,
    WebSocketManager
};

console.log('High-Speed Meme Bot initialized and ready to trade!');