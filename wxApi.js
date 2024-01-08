const CommonRequest = require('./commonRequest.js');
const logger = require('./../util/logger.js');
const crypto = require('crypto');
const keyDefines = require('./keyDefines.js');
const RedisLock = require('./redisLock.js');
const redis = require('./../library/db.js').redis;
const lodash = require('lodash');
const projectService = require('./../app/service/projectConfig.js');
const config = require('./../config/config.js');

//*****************************************微信示例************************************************
function WXBizDataCrypt(appId, sessionKey) {
    this.appId = appId;
    this.sessionKey = sessionKey;
}

WXBizDataCrypt.prototype.decryptData = function (encryptedData, iv) {
    // base64 decode
    let sessionKey = new Buffer(this.sessionKey, 'base64');
    encryptedData = new Buffer(encryptedData, 'base64');
    iv = new Buffer(iv, 'base64');

    try {
        // 解密
        let decipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, iv);
        // 设置自动 padding 为 true，删除填充补位
        decipher.setAutoPadding(true);
        var decoded = decipher.update(encryptedData, 'binary', 'utf8');
        decoded += decipher.final('utf8');

        decoded = JSON.parse(decoded)

    } catch (err) {
        throw new Error('Illegal Buffer')
    }

    if (decoded.watermark.appid !== this.appId) {
        throw new Error('Illegal Buffer')
    }

    return decoded;
};
//*****************************************微信示例************************************************

module.exports = {
    /**
     * 调用微信API获取sessionKey
     * @param code      前端调用wx.login时返回的用户凭证（时效5分钟）
     * @param appId
     * @param appSecret
     * @returns {Promise<void>}
     */
    getWXSessionKey: async function (code, appId, appSecret) {
        return await new CommonRequest()
            .get('https://api.weixin.qq.com/sns/jscode2session', {
                appid: appId,
                secret: appSecret,
                js_code: code,
                grant_type: 'authorization_code',
            }).toJson().ssl().go();
    },

    /**
     * 解密开放数据
     * @param appId
     * @param sessionKey    会话密钥
     * @param encryptedData 包括敏感数据在内的完整用户信息的加密数据
     * @param iv            加密算法的初始向量
     * @returns {any}
     */
    decryptData: function (appId, sessionKey, encryptedData, iv) {
        let pc = new WXBizDataCrypt(appId, sessionKey);
        return pc.decryptData(encryptedData , iv);
    },

    /**
     * 调用微信API获取access_token
     * @param appId
     * @param appSecret
     * @returns {Promise<void>}
     */
    getWXAccessToken: async function(appId, appSecret) {
        if (config.env !== 'prod') {
            return;
        }
        return await new CommonRequest()
            .get('https://api.weixin.qq.com/cgi-bin/token', {
                appid: appId,
                secret: appSecret,
                grant_type: 'client_credential',
            }).toJson().ssl().go();
    },

    /**
     * 根据project获取access_token
     * @param project
     * @returns {Promise<void>}
     */
    getWXAccessTokenByProject: async function(project) {
        let accessToken;
        let resRedisKey = keyDefines.projectWXAccessTokenRedisKey(project);
        let readLockRedisKey = keyDefines.projectWXAccessTokenReadLockRedisKey(project);
        let redisLock = new RedisLock().setLockRedisKey(readLockRedisKey).setResourceRedisKey(resRedisKey);
        let result = await redisLock.start();
        if (result && lodash.isBoolean(result)) { //返回的是锁
            let {appId, appSecret} = await projectService.getAppIdAndAppSecretByProject(project);
            let wxReqResult = await this.getWXAccessToken(appId, appSecret);
            if (wxReqResult.access_token && wxReqResult.expires_in) {
                accessToken = wxReqResult.access_token;
                // 在redis中缓存,缓存时间为微信提供的过期时间减去5分钟
                redis.set(resRedisKey, accessToken, "NX", "EX", wxReqResult.expires_in - keyDefines.TTL_FIVE_MIN);
            } else {
                logger.getLogger("error").error('getWXAccessTokenByProject出错, appId:%s, appSecret:%s, wxReqResult:%s',
                    appId, appSecret, JSON.stringify(wxReqResult));
            }
            redisLock.destroyLock();
        }
        else {// 返回的是资源会自动释放锁
            accessToken = result;
        }
        return accessToken;
    },

    /**
     * 调用微信API发送订阅消息
     * @param accessToken   微信调用凭证
     * @param project       项目名(若存在此项时,则优先通过项目名去redis取)
     * @param openid
     * @param templateId
     * @param page
     * @param data
     * @param miniProgramState 跳转小程序类型：developer为开发版；trial为体验版；formal为正式版；默认为正式版
     * @returns {Promise<void>}
     */
    reqWXSubMessageSend: async function({accessToken, project, openid, templateId, page, data = {}, miniProgramState}) {
        if (project) {
            accessToken = await this.getWXAccessTokenByProject(project);
        }
        if (!accessToken) {
            return;
        }
        let postData =  {
            touser: openid,
            template_id: templateId,
            data: data
        };
        if (page) {
            postData.page = page;
        }
        if (miniProgramState) {
            postData.miniprogramState = miniProgramState;
        }
        return await new CommonRequest()
            .post('https://api.weixin.qq.com/cgi-bin/message/subscribe/send',{
                access_token: accessToken,
            }, postData).toJson().ssl().go();
    },
};