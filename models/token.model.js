const mongoose = require('mongoose');

const tokenSchema = mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            ref: 'user'
        },
        // Verify Token
        vToken: {
            type: String,
            default: ''
        },
        // Reset Token
        rToken: {
            type: String,
            default: ''
        },
        // Login Token
        lToken: {
            type: String,
        },
        createdAt: {
            type: Date,
            required: true
        },
        expiresAt: {
            type: Date,
            required: true
        }
    }
);

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;