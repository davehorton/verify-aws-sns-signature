const bent = require('bent');
const getBuffer = bent('buffer');
const crypto = require('crypto');
const debug = require('debug')('verify-aws-sns-signature');
const assert = require('assert');

async function validatePayload(payload) {
  const {
    SigningCertURL,
    Signature,
    Message,
    MessageId,
    SubscribeURL,
    Subject,
    Timestamp,
    Token,
    TopicArn,
    Type
  } = payload;
  assert.ok([
    'SubscriptionConfirmation',
    'UnsubscribeConfirmation',
    'Notification'
  ].includes(Type), `invalid Type: ${Type}`);

  try {
    debug(`retrieving AWS certificate from ${SigningCertURL}`);

    const x509 = await getBuffer(SigningCertURL);
    const publicKey = crypto.createPublicKey(x509);
    const signature = Buffer.from(Signature, 'base64');
    const stringToSign = ('Notification' === Type ?
      [{Message}, {MessageId}, {Subject}, {Timestamp}, {TopicArn}, {Type}] :
      [{Message}, {MessageId}, {SubscribeURL}, {Timestamp}, {Token}, {TopicArn}, {Type}])
      .reduce((acc, el) => {
        const key = el.keys()[0];
        acc += key + '\n' + el[key] + '\n';
      }, '');

    debug(`string to sign: ${stringToSign}`);
    const verified = crypto.verify('sha1WithRSAEncryption', Buffer.from(stringToSign, 'utf8'), publicKey, signature);
    debug(`signature ${verified ? 'has been verified' : 'failed verification'}`);
    return verified;
  } catch (err) {
    return false;
  }
}

module.exports = {validatePayload};
