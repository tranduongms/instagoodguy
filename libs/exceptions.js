'use strict';

class CookieNotValidError extends Error {
    constructor(cookieName) {
        super(`Cookie "${cookieName}" you are searching found was either not found or not valid!`);
        this.name = 'CookieNotValidError';
        this.cookieName = cookieName;
    }
}

class LoginError extends Error {
    constructor(username) {
        super(`Account ${username} unable to login!`);
        this.name = 'LoginError';
        this.username = username;
    }
}

class AccountDisabledError extends Error {
    constructor(username) {
        super(`Account ${username} disabled!`);
        this.name = 'AccountDisabledError';
        this.username = username;
    }
}

class CheckpointChallengeError extends Error {
    constructor(username, challenge) {
        super(`Account ${username} checkpoint challenge!`);
        this.name = 'CheckpointChallengeError';
        this.username = username;
        this.challenge = challenge;
    }
}

module.exports = {
    CookieNotValidError,
    LoginError,
    AccountDisabledError,
    CheckpointChallengeError
}