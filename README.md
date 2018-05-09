# hapi-auth-twilio-sign
A [hapi.js](http://hapijs.com/) authentication plugin to validate [Twilio](https://www.twilio.com) webhook requests using signature.

This plugin will intercept the "X-Twilio-Signature" header token and validate it.

Works with HAPI v16.

USAGE:

```js
const twilioAccountAuthToken = process.env.TWILIO_ACCOUNT_AUTH_TOKEN

const HapiAuthTwilio = require('hapi-auth-twilio-sign');

server.register(HapiAuthTwilio, function (err) {
    if (err) throw err
    HapiAuthTwilio.strategy(server, twilioAccountAuthToken);
    server.route({ method: 'POST', path: '/twilio-webhooks', config: { auth: 'twilio' } });
});
```
