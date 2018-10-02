'use strict';

function CookieNotValidError(cookieName) {
    this.name = 'CookieNotValidError';
    this.message = "Cookie `" + cookieName + "` you are searching found was either not found or not valid!";
}

function LoginError() {
    this.name = 'LoginError';
    this.message = `Login error!`;
}

module.exports = {
    CookieNotValidError,
    LoginError
}