'use strict'

const boom = require('boom')
const hoek = require('hoek')
const Twilio = require('twilio')

// Declare internals
const internals = {}

exports.register = function (server, options, next) {
  server.auth.scheme('twilio-signature', internals.implementation)
  next()
}

exports.register.attributes = {
  pkg: require('../package.json')
}

internals.implementation = function (server, options) {

  hoek.assert(options, 'Missing header "X-Twilio-Signature" for authentication.')
  hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a function to validate authentication.')

  let settings = hoek.clone(options)
  settings.twilioSignature = settings.twilioSignature || 'x-twilio-signature'

  const scheme = {
    authenticate: function (request, reply) {
      let signature = request.headers[settings.twilioSignature]
      if (!signature) {
        return reply(boom.unauthorized('X-Twilio-Signature is not set', 'twilio-signature'))
      }
      return reply.continue({
        credentials: settings.credentials || {}
      })
    },
    payload: function (request, reply) {
      let signature = request.headers[settings.twilioSignature]
      if (!signature) {
        return reply(boom.unauthorized('X-Twilio-Signature is not set', 'twilio-signature'))
      }

      if (settings.validateFunc) {
        settings.validateFunc(request, signature, function (err, isValid) {
          if (err || !isValid) {
            return reply(boom.unauthorized('Bad Twilio Signature', 'Signature'), null)
          } else {
            return reply.continue()
          }
        })
      } else {
        return reply.continue()
      }

    }
  }

  return scheme
}


/**
 * This is a demo strategy
 *
 * @param {Object} server - the hapi server instance
 * @param {String} twilioAccountAuthToken - the twilio account auth token
 * @example
 * server.register(HapiAuthTwilioSign, function (err) {
 *    if (err) throw err
 *    HapiAuthTwilioSign.strategy(server, twilioAccountAuthToken)
 * }
 */
exports.strategy = function (server, twilioAccountAuthToken) {
  server.auth.strategy('twilio', 'twilio-signature', {

    /**
     * validateFunc
     * Used to validate that the request has a twilio signature (came from twilio) and corresponding payload
     * @param request - request.
     * @param signature - a header signature sent from twilio via "X-Twilio-Signature".
     * @param callback - a callback function with the signature function(err, isValid, credentials)
     */
    validateFunc (request, signature, callback) {
      if (!signature) {
        return callback(null, false)
      }

      const url = request.connection.info.protocol +
        (request.headers['x-forwarded-proto'] === 'https' ? 's' : '') +
        '://' +
        request.info.host +
        request.url.path
      const payload = request.payload || {}
      if (!Twilio.validateRequest(twilioAccountAuthToken, signature, url, payload)) {
        return callback(null, false)
      }

      callback(null, true)
    }

  })
}
