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

const constants = require('./constants');
const Exceptions = require('./exceptions');


class Client {
    constructor(username, password, proxy) {
        this.username = username;
        this.password = password;
        this.proxy = proxy;
        let storePath = path.join(os.tmpdir(), this.username + '.json');
        if (!fs.existsSync(storePath)) {
            fs.writeFileSync(storePath, '');
        }
        this.cookieStore = new FileCookieStore(storePath);
        this.jar = request.jar(this.cookieStore);
        this.request = request.defaults({
            headers: this.defaultHeaders(),
            timeout: 60000,
            proxy: proxy,
            jar: this.jar,
            gzip: true
        })
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
        if (process.env.NODE_DEBUG && process.env.NODE_DEBUG.indexOf('instagoodgy') >= 0) {
            console.log(`[DEBUG] Enpoint ${enpoint}; option: ${JSON.stringify(option)}`);
        }
        return this.request.post(url, option);
    }

    async login() {
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
            throw Exceptions.LoginError('Unable to login!');
        } else {
            this.loggedIn = true;
            this.csrfToken = await this.getCsrfToken();
            this.authenticatedUserId = await this.getAuthenticatedUserId();
            console.log(`Account ${this.username}(${jsonRes.logged_in_user.full_name}) login success`);
        }
    }

    async currentUser() {
        if (!this.loggedIn) return;
        return this.callApi('accounts/current_user/', {
            form: this.getAuthenticatedParams(),
            qs: { 'edit': 'true' }
        }).then(res => res.user);
    }

    async checkUsername(username) {
        return this.callApi('users/check_username/', { form: { username } });
    }

    async updateProfile(update = {}) {
        if (!this.loggedIn) return;
        let user = await this.currentUser();
        let profile = {
            'username': user.username,
            'gender': user.gender,
            'phone_number': user.phone_number,
            'first_name': user.full_name,
            'biography': user.biography,
            'external_url': user.external_url,
            'email': user.email
        };
        profile = Object.assign({}, profile, update);
        console.log(`Account ${user.username} update profile to ${JSON.stringify(profile)}`);
        return this.callApi('accounts/edit_profile/', { form: Object.assign({}, profile, this.getAuthenticatedParams()) });
    }

    removeProfilePicture() {
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

    async getDetailByUserId(userId) {
        console.warn(`WARNING: The "users/user_id/full_detail_info/" endpoint is experimental. Be carefully use!`);
        return this.callApi(`users/${userId}/full_detail_info/`);
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
}

module.exports = Client;
