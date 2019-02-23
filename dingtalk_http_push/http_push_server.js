var getRawBody = require('raw-body');
var getFormBody = require("body/form");
var body = require('body');
var crypto = require('crypto');

const config = {
  oapiHost: 'https://oapi.dingtalk.com',
  token: '', //创建套件时自定义的token
  encodingAESKey: '', //创建套件时填写的加密秘钥
  suiteKey: '', //套件key，当还没有创建套件时，请留空
  suiteSecret: '' //套件secret，创建套件后才有，当还没有创建套件时可留空，创建成功后需要更新该值
};

/**
 * 提供基于PKCS7算法的加解密接口
 *
 */
var PKCS7Encoder = {};

/**
 * 删除解密后明文的补位字符
 *
 * @param {String} text 解密后的明文
 */
PKCS7Encoder.decode = function (text) {
  var pad = text[text.length - 1];

  if (pad < 1 || pad > 32) {
    pad = 0;
  }

  return text.slice(0, text.length - pad);
};

/**
 * 对需要加密的明文进行填充补位
 *
 * @param {String} text 需要进行填充补位操作的明文
 */
PKCS7Encoder.encode = function (text) {
  var blockSize = 32;
  var textLength = text.length;
  //计算需要填充的位数
  var amountToPad = blockSize - (textLength % blockSize);

  var result = new Buffer(amountToPad);
  result.fill(amountToPad);

  return Buffer.concat([text, result]);
};

/**
 * 加解密信息构造函数
 *
 * @param {String} token          第三方企业E应用平台上，开发者设置的Token
 * @param {String} encodingAESKey 第三方企业E应用平台上，开发者设置的EncodingAESKey
 * @param {String} id             对于ISV来说，填写对应的suitekey； 对于普通企业开发，填写企业的Corpid
 */
var DDBizMsgCrypt = function (token, encodingAESKey, id) {
  if (!token || !encodingAESKey || !id) {
    throw new Error('please check arguments');
  }
  this.token = token;
  this.id = id;
  var AESKey = new Buffer(encodingAESKey + '=', 'base64');
  if (AESKey.length !== 32) {
    throw new Error('encodingAESKey invalid');
  }
  this.key = AESKey;
  this.iv = AESKey.slice(0, 16);
};

/**
 * 获取签名
 *
 * @param {String} timestamp    时间戳
 * @param {String} nonce        随机数
 * @param {String} encrypt      加密后的文本
 */
DDBizMsgCrypt.prototype.getSignature = function (timestamp, nonce, encrypt) {
  var shasum = crypto.createHash('sha1');
  var arr = [this.token, timestamp, nonce, encrypt].sort();
  shasum.update(arr.join(''));

  return shasum.digest('hex');
};

/**
 * 对密文进行解密
 *
 * @param {String} text 待解密的密文
 */
DDBizMsgCrypt.prototype.decrypt = function (text) {
  // 创建解密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
  var decipher = crypto.createDecipheriv('aes-256-cbc', this.key, this.iv);
  decipher.setAutoPadding(false);
  var deciphered = Buffer.concat([decipher.update(text, 'base64'), decipher.final()]);

  deciphered = PKCS7Encoder.decode(deciphered);
  // 算法：AES_Encrypt[random(16B) + msg_len(4B) + msg + $CorpID]
  // 去除16位随机数
  var content = deciphered.slice(16);
  var length = content.slice(0, 4).readUInt32BE(0);

  return {
    message: content.slice(4, length + 4).toString(),
    id: content.slice(length + 4).toString()
  };
};

/**
 * 对明文进行加密
 *
 * @param {String} text 待加密的明文
 */
DDBizMsgCrypt.prototype.encrypt = function (text) {
  // 算法：AES_Encrypt[random(16B) + msg_len(4B) + msg + $CorpID]
  // 获取16B的随机字符串
  var randomString = crypto.pseudoRandomBytes(16);

  var msg = new Buffer(text);

  // 获取4B的内容长度的网络字节序
  var msgLength = new Buffer(4);
  msgLength.writeUInt32BE(msg.length, 0);

  var id = new Buffer(this.id);

  var bufMsg = Buffer.concat([randomString, msgLength, msg, id]);

  // 对明文进行补位操作
  var encoded = PKCS7Encoder.encode(bufMsg);

  // 创建加密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
  var cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv);
  cipher.setAutoPadding(false);

  var cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);

  // 返回加密数据的base64编码
  return cipheredMsg.toString('base64');
};

var Cipher = new DDBizMsgCrypt(config.token, config.encodingAESKey, config.suiteKey);

/*
if you open the initializer feature, please implement the initializer function, as below:
module.exports.initializer = function(context, callback) {
    console.log("initializing");
    callback(null, "");
};
*/

module.exports.handler = function (req, resp, context) {
  var params = {
    path: req.path,
    queries: req.queries,
    headers: req.headers,
    method: req.method,
    requestURI: req.url,
    clientIP: req.clientIP,
  }

  getRawBody(req, function (err, body) {
    var json = JSON.parse(body);
    var encrypt = json.encrypt;

    //解密推送信息
    var data = Cipher.decrypt(encrypt);
    //解析数据结构
    var json = JSON.parse(data.message) || {};
    var msg = '';
    //处理不同类型的推送数据
    switch (json.EventType) {
      // 验证新创建的回调URL有效性
      case 'check_create_suite_url':
        msg = 'success';
        break;
      // 验证更新回调URL有效性
      case 'check_update_suite_url':
        msg = 'success';
        break;
      // 应用suite_ticket数据推送
      //suite_ticket用于用签名形式生成accessToken(访问钉钉服务端的凭证)，需要保存到应用的db。
      //钉钉会定期向本callback url推送suite_ticket新值用以提升安全性。
      //应用在获取到新的时值时，保存db成功后，返回给钉钉success加密串（如本demo的return）
      case 'suite_ticket':
        msg = 'success';
        break;
      // 企业授权开通应用事件
      //本事件应用应该异步进行授权开通企业的初始化，目的是尽最大努力快速返回给钉钉服务端。用以提升企业管理员开通应用体验
      //即使本接口没有收到数据或者收到事件后处理初始化失败都可以后续再用户试用应用时从前端获取到corpId并拉取授权企业信息，
      // 进而初始化开通及企业。
      case 'tmp_auth_code':
        msg = 'success';
        break;
      default:
      // 其他类型事件处理
    }
    //加密文本
    var text = Cipher.encrypt(msg);
    //生成随机串
    var stmp = Date.now();
    //生成随机数
    var nonce = Math.random().toString(36).substring(2);

    //签名文本
    var sign = Cipher.getSignature(stmp, nonce, text);

    //返回给推送服务器的信息
    var result = {
      msg_signature: sign,
      timeStamp: stmp,
      nonce: nonce,
      encrypt: text
    };
    resp.send(JSON.stringify(result, null, '    '));
  });
}
