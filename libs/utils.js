'use strict';

const CryptoJS = require('crypto-js');

function generateUserBreadcrumb(size) {
    // Used in comments posting.
    let key = 'iN4$aGr0m';
    let dt = Date.now();

    // typing time elapsed
    let timeElapsed = Math.round(500 + Math.random() * 1000) + size * Math.round(500 + Math.random() * 1000);

    let textChangeEventCount = Math.max(1, Math.floor(size / Math.round(3 + Math.random() * 2)));

    let data = `${size} ${timeElapsed} ${textChangeEventCount} ${dt}`;

    return CryptoJS.enc.Base64.stringify(CryptoJS.HmacSHA256(data, key)) + '\n' + Buffer.from(data).toString('base64') + '\n';
}

module.exports = {
    generateUserBreadcrumb
}