'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');
const request = require('request-promise');
const FileCookieStore = require('tough-cookie-filestore');
const md5 = require('js-md5');
const uuid4 = require('uuid/v4');
const hmac = require('crypto-js/hmac-sha256');
const sizeOf = require('image-size');
const requestErrors = require('request-promise/errors');

const utils = require('./utils');
const constants = require('./constants');
const Exceptions = require('./exceptions');


class Client {
    constructor(username, password, proxy, oldCookiesString) {
        this.username = username;
        this.password = password;
        this.proxy = proxy;
        this.oldCookiesString = oldCookiesString;
        this.storePath = path.join(os.tmpdir(), this.username + '.json');
        if (!fs.existsSync(this.storePath)) {
            if (typeof (oldCookiesString) == 'string') {
                this._importOldCookies(oldCookiesString);
            } else {
                fs.writeFileSync(this.storePath, '');
            }
        } else {
            let data = fs.readFileSync(this.storePath).toString();
            try {
                JSON.parse(data);
            } catch (err) {
                if (typeof (oldCookiesString) == 'string') {
                    this._importOldCookies(oldCookiesString);
                } else {
                    fs.writeFileSync(this.storePath, '');
                }
            }
        }
        if (!this.cookieStore) this.cookieStore = new FileCookieStore(this.storePath);
        if (!this.jar) this.jar = request.jar(this.cookieStore);
        this.request = request.defaults({
            headers: this.defaultHeaders(),
            timeout: 180000,
            proxy: proxy,
            jar: this.jar,
            gzip: true
        });
        this.uuid = uuid4();
        this.deviceId = this.getDeviceId();
        this.adId = this.getAdId();
        this.phoneId = uuid4();
        this.loggedIn = false;
    }

    defaultHeaders() {
        return {
            'User-Agent': constants.USER_AGENT,
            'Connection': 'close',
            'Accept': '*/*',
            'Accept-Language': 'en-US',
            'Accept-Encoding': 'gzip, deflate',
            'X-IG-Capabilities': constants.IG_CAPABILITIES,
            'X-IG-Connection-Type': 'WIFI',
            'X-IG-Connection-Speed': `${Math.round(1000 + Math.random() * 4000)}kbps`,
            'X-IG-App-ID': constants.APPLICATION_ID,
            'X-IG-Bandwidth-Speed-KBPS': '-1.000',
            'X-IG-Bandwidth-TotalBytes-B': '0',
            'X-IG-Bandwidth-TotalTime-MS': '0',
            'X-FB-HTTP-Engine': constants.FB_HTTP_ENGINE
        }
    }

    getCookieValue(name) {
        let that = this;
        return new Promise(function (resolve, reject) {
            that.cookieStore.findCookie(constants.HOST, '/', name, function (err, cookie) {
                if (err) return reject(err);
                if (!cookie || !cookie.value) return reject(new Exceptions.CookieNotValidError(name));
                resolve(cookie);
            })
        });
    }

    getCookies() {
        let that = this;
        return new Promise(function (resolve, reject) {
            that.cookieStore.findCookies(constants.HOST, '/', function (err, cookies) {
                if (err) return reject(err);
                resolve(cookies || []);
            })
        });
    }

    _importOldCookies(oldCookiesString) {
        try {
            console.log(`Account ${this.username} import old cookies to ${this.storePath}`);
            fs.writeFileSync(this.storePath, '');
            let old = JSON.parse(oldCookiesString);
            if (old && (old instanceof Array) && old.length > 0) {
                this.cookieStore = new FileCookieStore(this.storePath);
                this.jar = request.jar(this.cookieStore);
                for (let i = 0; i < old.length; i++) {
                    let cookie = old[i];
                    let domain = (cookie.Domain || cookie.domain);
                    let url = domain.replace(/^\.+/, 'www.');
                    let path = cookie.Path || cookie.path || '/';
                    let key = cookie.Name || cookie.name || cookie.key;
                    let value = cookie.Value || cookie.value;
                    this.jar.setCookie(`${key}=${value}; Domain=${domain}; Path=${path}`, `https://${url}${path}`);
                }
            } else {
                throw new Error('oldCookiesString should be JSON stringify of array of cookies');
            }
        } catch (err) {
            console.error('Error using old cookies', err.message);
        }
    }

    getCsrfToken() {
        return this.getCookieValue('csrftoken')
            .then(cookie => cookie.value);
    }

    getAuthenticatedUserId() {
        return this.getCookieValue('ds_user_id')
            .then(cookie => {
                let id = parseInt(cookie.value);
                if (id && !Number.isNaN(id)) {
                    return id;
                } else {
                    throw new Exceptions.CookieNotValidError('ds_user_id');
                }
            })
    }

    getAuthenticatedUserName() {
        return this.getCookieValue('ds_user')
            .then(cookie => {
                if (cookie.value) {
                    return cookie.value;
                } else {
                    throw new Exceptions.CookieNotValidError('ds_user');
                }
            })
    }

    getDeviceId() {
        return 'android-' + md5(this.username).slice(0, 16);
    }

    getAdId(seed) {
        let modified = seed || this.username;
        if (modified) {
            let sha2 = require('crypto').createHash('sha256');
            sha2.update(modified);
            modified = sha2.digest('hex');
        }
        return md5(modified);
    }

    getAuthenticatedParams() {
        return {
            '_csrftoken': this.csrfToken,
            '_uuid': this.uuid,
            '_uid': this.authenticatedUserId
        }
    }

    callApi(enpoint, data = {}, jsonResponse = true, signData = true, version = 'v1') {
        let url = constants.API_URL + version + '/' + enpoint;
        let option = {
            headers: Object.assign({}, data.headers),
            qs: data.qs,
            body: data.body,
            json: jsonResponse
        }
        if (data.form) {
            if (signData) {
                let jsonData = JSON.stringify(data.form);
                let hashSigned = hmac(jsonData, constants.IG_SIG_KEY);
                option.form = {
                    'ig_sig_key_version': constants.SIG_KEY_VERSION,
                    'signed_body': hashSigned + '.' + jsonData
                }
            } else {
                option.form = data.form;
            }
            option.headers['Content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
        } else if (data.formData) {
            if (signData) {
                let jsonData = JSON.stringify(this.getAuthenticatedParams());
                let hashSigned = hmac(jsonData, constants.IG_SIG_KEY);
                option.formData = Object.assign({}, {
                    'ig_sig_key_version': constants.SIG_KEY_VERSION,
                    'signed_body': hashSigned + '.' + jsonData
                }, data.formData);
            } else {
                option.formData = data.formData;
            }
            option.headers['Content-type'] = 'multipart/form-data; charset=UTF-8';
        }
        return this.request
            .post(url, option)
            .catch(requestErrors.StatusCodeError, err => {
                if (err.statusCode == 400) {
                    if (typeof (err.error) == 'string') {
                        err.error = JSON.parse(err.error);
                    }
                    if (err.error.challenge) {
                        throw new Exceptions.CheckpointChallengeError(this.username, err.error.challenge);
                    } else if (err.error.message && (err.error.message.indexOf('account has been disabled') >= 0)) {
                        throw new Exceptions.AccountDisabledError(this.username);
                    } else {
                        throw err;
                    }
                } else {
                    throw err;
                }
            });
    }

    async login() {
        if (this.proxy) {
            console.log(`Account ${this.username} login using proxy ${this.proxy}`);
        }
        await this.callApi(
            'si/fetch_headers/',
            {
                qs: {
                    'challenge_type': 'signup',
                    'guid': uuid4()
                }
            },
            false
        );
        let csrfToken = await this.getCsrfToken();
        let loginData = {
            'device_id': this.deviceId,
            'guid': this.uuid,
            'adid': this.adId,
            'phone_id': this.phoneId,
            '_csrftoken': csrfToken,
            'username': this.username,
            'password': this.password,
            'login_attempt_count': '0',
        }
        let jsonRes = await this.callApi('accounts/login/', { form: loginData });
        if (!jsonRes.logged_in_user || !jsonRes.logged_in_user.pk) {
            throw Exceptions.LoginError(this.username);
        } else {
            this.loggedIn = true;
            this.csrfToken = await this.getCsrfToken();
            this.authenticatedUserId = await this.getAuthenticatedUserId();
            console.log(`Account ${this.username}(${jsonRes.logged_in_user.full_name}) login success`);
        }
    }

    async currentUser() {
        return this.callApi('accounts/current_user/', {
            form: this.getAuthenticatedParams(),
            qs: { 'edit': 'true' }
        }).then(res => res.user);
    }

    async checkUsername(username) {
        return this.callApi('users/check_username/', { form: { username } }).then(res => (res.status == 'ok' && res.available));
    }

    async updateProfile(update = {}) {
        let user = await this.currentUser();
        let profile = {
            'username': user.username,
            'gender': user.gender || 1,
            'phone_number': user.phone_number || '',
            'first_name': user.full_name || '',
            'biography': user.biography || '',
            'external_url': user.external_url || '',
            'email': user.email
        };
        profile = Object.assign({}, profile, update);
        console.log(`Account ${user.username} update profile to ${JSON.stringify(profile)}`);
        return this.callApi('accounts/edit_profile/', { form: Object.assign({}, profile, this.getAuthenticatedParams()) });
    }

    async removeProfilePicture() {
        return this.callApi('accounts/remove_profile_picture/', { form: this.getAuthenticatedParams() })
    }

    async changeProfilePicture(photoPath) {
        if (!fs.existsSync(photoPath)) {
            throw {
                name: 'ChangeProfileError',
                message: `Photo ${photoPath} not existed!`
            }
        } else {
            return this.callApi('accounts/change_profile_picture/', {
                formData: {
                    profile_pic: {
                        value: fs.createReadStream(photoPath),
                        options: {
                            filename: 'profile_pic',
                            contentType: 'image/jpeg'
                        }
                    }
                }
            });
        }
    }

    async getInfoByUserId(userId) {
        return this.callApi(`users/${userId}/info/`);
    }

    async getInfoByUsername(username) {
        return this.callApi(`users/${username}/usernameinfo/`);
    }

    async getFeedByUserId(userId, qs) {
        return this.callApi(`feed/user/${userId}/`, { qs });
    }

    async getFeedByUsername(username, qs) {
        return this.callApi(`feed/user/${username}/username/`, { qs });
    }

    async getMyFeed(qs) {
        let id = await this.getAuthenticatedUserId();
        return this.getFeedByUserId(id, qs);
    }

    async configPhoto(uploadId, size, caption, disableComments, isSidecar) {
        let config = {
            'caption': caption,
            'media_folder': 'Instagram',
            'source_type': '4',
            'upload_id': uploadId,
            'device': {
                'manufacturer': constants.PHONE_MANUFACTURER,
                'model': constants.PHONE_MODEL,
                'android_version': constants.ANDROID_VERSION,
                'android_release': constants.ANDROID_RELEASE
            },
            'edits': {
                'crop_original_size': [size.width * 1.0, size.height * 1.0],
                'crop_center': [0.0, -0.0],
                'crop_zoom': 1.0
            },
            'extra': {
                'source_width': size.width,
                'source_height': size.height,
            }
        }
        if (disableComments) config['disable_comments'] = '1';
        if (isSidecar) return config;
        return this.callApi('media/configure/', { form: Object.assign({}, config, this.getAuthenticatedParams()) });
    }

    async postPhoto(photoPath, caption = '', disableComments = false, isSidecar = false) {
        if (!fs.existsSync(photoPath)) {
            throw {
                name: 'PostPhotoError',
                message: `Photo ${photoPath} not existed!`
            }
        } else {
            let uploadId = Date.now().toString();
            let size = sizeOf(photoPath);
            let formData = {
                upload_id: uploadId,
                _uuid: this.uuid,
                _csrftoken: this.csrfToken,
                image_compression: '{"lib_name":"jt","lib_version":"1.3.0","quality":"87"}',
                photo: {
                    value: fs.createReadStream(photoPath),
                    options: {
                        filename: `pending_media_${uploadId}`,
                        contentType: 'image/jpeg'
                    }
                }
            }
            let res = await this.callApi('upload/photo/', { formData });
            if (res.status == 'ok' && res.upload_id) {
                await new Promise(res => setTimeout(res, 4000));
                return this.configPhoto(res.upload_id, size, caption, disableComments, isSidecar);
            } else {
                throw {
                    name: 'UploadPhotoError',
                    message: `Upload photo ${photoPath} error with res ${JSON.stringify(res)}`
                }
            }
        }
    }

    async getMediaInfo(mediaId) {
        return this.callApi(`media/${mediaId}/info/`);
    }

    async deleteMedia(mediaId) {
        return this.callApi(`media/${mediaId}/delete/`,
            {
                form: Object.assign({}, this.getAuthenticatedParams(), { media_id: mediaId })
            }
        );
    }

    async postComment(mediaId, comment) {
        if (comment.length > 300) {
            throw new TypeError('The total length of the comment cannot exceed 300 characters.');
        }
        let hashtags = comment.match(/#[^#]+\b/g);
        if (hashtags && hashtags.length > 4) {
            throw new TypeError('The comment cannot contain more than 4 hashtags.');
        }
        let urls = comment.match(/\bhttps?:\/\/\S+\.\S+/g);
        if (urls && urls.length > 1) {
            throw new TypeError('The comment cannot contain more than 1 URL.');
        }
        let endpoint = `media/${mediaId}/comment/`;
        let params = {
            'comment_text': comment,
            'user_breadcrumb': utils.generateUserBreadcrumb(comment.length),
            'idempotence_token': uuid4(),
            'containermodule': 'comments_feed_timeline',
            'radio_type': 'wifi-none',
        }
        return this.callApi(endpoint, { form: Object.assign({}, params, this.getAuthenticatedParams()) });
    }

    async postLike(mediaId, moduleName = 'feed_timeline') {
        // param module_name: Example: 'feed_timeline', 'video_view', 'photo_view'
        let endpoint = `media/${mediaId}/like/`;
        let params = {
            'media_id': mediaId,
            'module_name': moduleName,
            'radio_type': 'wifi-none',
        }
        // d query param = flag for double tap
        return this.callApi(endpoint, { form: Object.assign({}, params, this.getAuthenticatedParams()), qs: { 'd': '1' } });
    }

    async followUser(userId) {
        let endpoint = `friendships/create/${userId}/`;
        let params = {
            'user_id': userId,
            'radio_type': 'wifi-none'
        };
        return this.callApi(endpoint, { form: Object.assign({}, params, this.getAuthenticatedParams()) });
    }

    async passChallenge(error, getPhoneNumberPromise, getPhoneCodePromise, getEmailCodePromise, method = 'email') {
        let req = request.defaults({
            headers: {
                'Connection': 'close',
                'Accept': '*/*',
                'Accept-Language': 'en-US',
                'Accept-Encoding': 'gzip, deflate',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'no-cache',
                'User-Agent': constants.IPHONE_USER_AGENT,
                'Pragma': 'no-cache'
            },
            timeout: 120000,
            json: true,
            gzip: true,
            jar: this.jar,
            proxy: this.proxy,
            followRedirect: true
        });
        let res;
        if (error instanceof Exceptions.CheckpointChallengeError) {
            let apiUrl = 'https://i.instagram.com/api/v1' + error.challenge.api_path;
            res = await req.post(apiUrl.replace('/challenge/', '/challenge/reset/'));
            res.apiUrl = apiUrl;
            return this.passChallenge(res, getPhoneNumberPromise, getPhoneCodePromise, getEmailCodePromise, method);
        } else {
            if (error.step_name == 'select_verify_method') {
                res = await req.post(error.apiUrl, {
                    form: { choice: method === 'email' ? 1 : 0 }
                });
                res.apiUrl = error.apiUrl;
                return this.passChallenge(res, getPhoneNumberPromise, getPhoneCodePromise, getEmailCodePromise, method);
            } else if (!error.step_name || (error.step_name == 'submit_phone')) {
                let number;
                if (typeof getPhoneNumberPromise == 'function') {
                    try {
                        number = await getPhoneNumberPromise();
                        console.log(`Got phone number ${number}`);
                    } catch (err) {
                        throw new Error(`Can't get phone number from getPhoneNumberPromise`);
                    }
                } else {
                    if (error.step_data && error.step_data.phone_number) {
                        number = error.step_data.phone_number;
                    } else {
                        throw new Error(`Can't get phone number from instagram`);
                    }
                }
                // Submit phone number
                res = await req.post(error.apiUrl, {
                    form: { phone_number: number }
                });
                res.apiUrl = error.apiUrl;
                res.number = number;
                return this.passChallenge(res, getPhoneNumberPromise, getPhoneCodePromise, getEmailCodePromise, method);
            } else if (error.step_name == 'verify_code' || error.step_name == 'verify_email') {
                let code;
                if (!error.step_data || (error.step_data.form_type == 'phone_number')) {
                    try {
                        console.log(`Waiting for verify code sent to phone`);
                        code = await getPhoneCodePromise(error.number);
                        console.log(`Got verify code send to phone ${code}`);
                    } catch (err) {
                        throw new Error(`Can't get verify code from getPhoneCodePromise`);
                    }
                } else if (error.step_data.form_type == 'email') {
                    try {
                        console.log(`Waiting for verify code sent to email`);
                        await new Promise(res => setTimeout(res, 30000));
                        code = await getEmailCodePromise(error.step_data.contact_point);
                        console.log(`Got verify code send to email ${code}`);
                    } catch (err) {
                        throw new Error(`Can't get verify code from getEmailCodePromise`);
                    }
                }
                if (!code || code.length != 6) {
                    throw new Error(`Verify code ${code} is not valid`);
                }
                // Submit verify code
                console.log(`Submit verify code ${code}`);
                await req.post(error.apiUrl, {
                    form: { security_code: code }
                }).catch(requestErrors.StatusCodeError, err => {
                    throw new Error(`Can't bypass challenge, ${err.message}`);
                });
                console.log(`Pass challenge success`);
            } else if (error.step_name == 'delta_login_review') {
                try {
                    let csrfToken = await this.getCsrfToken();
                    await req.post(error.apiUrl, {
                        form: {
                            approve: 'It Was Me',
                            csrfmiddlewaretoken: csrfToken
                        }
                    }).catch(requestErrors.StatusCodeError, err => {
                        if (err.statusCode == 302)
                            return;
                        else
                            throw err;
                    });
                    res = await req.post(error.apiUrl, {
                        form: {
                            OK: 'OK',
                            csrfmiddlewaretoken: csrfToken
                        }
                    });
                    console.log(`Pass challenge success`);
                } catch (err) {
                    throw new Error(`Can't verify "It Was Me": ${JSON.stringify(err)}`);
                }
            } else {
                throw new Error(`Verify method not supported: ${JSON.stringify(error)}`);
            }
        }
    }
}

module.exports = Client;
