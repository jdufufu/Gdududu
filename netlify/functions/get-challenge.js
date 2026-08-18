const crypto = require('crypto');

exports.handler = async (event) => {
    // Only allow GET requests
    if (event.httpMethod !== 'GET') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    const address = event.queryStringParameters.address;

    if (!address) {
        return {
            statusCode: 400,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "Wallet address is required" })
        };
    }

    // Generate a unique nonce and timestamp
    const nonce = crypto.randomBytes(8).toString('hex');
    const timestamp = Date.now();

    // Standardized authentication message
    const message = `Sign in to access the platform.\n\nAddress: ${address.toLowerCase()}\nNonce: ${nonce}\nTimestamp: ${timestamp}`;

    return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, timestamp, nonce })
    };
};
