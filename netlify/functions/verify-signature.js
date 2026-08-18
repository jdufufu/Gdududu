const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_key_change_me';

exports.handler = async (event) => {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    try {
        const { address, signature, message, timestamp } = JSON.parse(event.body);

        if (!address || !signature || !message || !timestamp) {
            return {
                statusCode: 400,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ error: "Missing required authentication fields." })
            };
        }

        const fiveMinutes = 5 * 60 * 1000;
        if (Date.now() - timestamp > fiveMinutes) {
            return {
                statusCode: 400,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ error: "Signature expired. Please try again." })
            };
        }

        const recoveredAddress = ethers.verifyMessage(message, signature);

        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
            return {
                statusCode: 401,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ error: "Invalid signature. Verification failed." })
            };
        }

        const token = jwt.sign(
            { address: address.toLowerCase() },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                success: true,
                token: token,
                address: address.toLowerCase()
            })
        };

    } catch (err) {
        return {
            statusCode: 500,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "Server verification error: " + err.message })
        };
    }
};
