'use strict'

const boom = require('boom')
const hoek = require('hoek')

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
        return reply(boom.unauthorized('X-Twilio-Signature is not set', 'Twilio-Signature'))
      }
      return reply.continue({
        credentials: settings.credentials || {}
      })
    },
    payload: function (request, reply) {
      let signature = request.headers[settings.twilioSignature]
      if (!signature) {
        return reply(boom.unauthorized('X-Twilio-Signature is not set', 'Twilio-Signature'))
      }

      if (settings.validateFunc) {
        settings.validateFunc(request, signature, function (err, isValid) {
          if (err) {
            return reply(err, null, {log: {tags: ['auth', 'Twilio-Signature'], data: err}})
          }
          if (!isValid) {
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
