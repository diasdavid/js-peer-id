/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-env mocha */
'use strict'
require('loud-rejection')()
const expect = require('chai').expect
const crypto = require('libp2p-crypto')
const mh = require('multihashes')
const parallel = require('async/parallel')

const PeerId = require('../src')

const testId = require('./fixtures/sample-id')
const testIdHex = testId.id
const testIdBytes = mh.fromHexString(testId.id)
const testIdB58String = mh.toB58String(testIdBytes)

const goId = require('./fixtures/go-private-key')

describe('PeerId', () => {
  it('create an id without \'new\'', () => {
    expect(PeerId).to.throw(Error)
  })

  it('create a new id', (done) => {
    PeerId.create((err, id) => {
      expect(err).to.not.exist
      expect(id.toB58String().length).to.equal(46)
      done()
    })
  })

  it('recreate an Id from Hex string', () => {
    const id = PeerId.createFromHexString(testIdHex)
    expect(testIdBytes).to.deep.equal(id.id)
  })

  it('Recreate an Id from a Buffer', () => {
    const id = PeerId.createFromBytes(testIdBytes)
    expect(testId.id).to.equal(id.toHexString())
  })

  it('Recreate a B58 String', () => {
    const id = PeerId.createFromB58String(testIdB58String)
    expect(testIdB58String).to.equal(id.toB58String())
  })

  it('Recreate from a Public Key', (done) => {
    PeerId.createFromPubKey(testId.pubKey, (err, id) => {
      expect(err).to.not.exist
      expect(testIdB58String).to.equal(id.toB58String())
      done()
    })
  })

  it('Recreate from a Private Key', (done) => {
    PeerId.createFromPrivKey(testId.privKey, (err, id) => {
      expect(err).to.not.exist
      expect(testIdB58String).to.equal(id.toB58String())

      const encoded = new Buffer(testId.privKey, 'base64')
      PeerId.createFromPrivKey(encoded, (err, id2) => {
        expect(err).to.not.exist
        expect(testIdB58String).to.equal(id2.toB58String())
        done()
      })
    })
  })

  it('Compare generated ID with one created from PubKey', (done) => {
    PeerId.create((err, id1) => {
      expect(err).to.not.exist

      PeerId.createFromPubKey(id1.marshalPubKey(), (err, id2) => {
        expect(err).to.not.exist
        expect(id1.id).to.be.eql(id2.id)
        done()
      })
    })
  })

  it('Non-default # of bits', (done) => {
    PeerId.create({ bits: 1024 }, (err, shortId) => {
      expect(err).to.not.exist
      PeerId.create({ bits: 4096 }, (err, longId) => {
        expect(err).to.not.exist
        expect(shortId.privKey.bytes.length).is.below(longId.privKey.bytes.length)
        done()
      })
    })
  })

  it('Pretty printing', (done) => {
    PeerId.create((err, id1) => {
      expect(err).to.not.exist
      PeerId.createFromPrivKey(id1.toPrint().privKey, (err, id2) => {
        expect(err).to.not.exist
        expect(id1.toPrint()).to.be.eql(id2.toPrint())
        done()
      })
    })
  })

  it('toBytes', () => {
    const id = PeerId.createFromHexString(testIdHex)
    expect(id.toBytes().toString('hex')).to.equal(testIdBytes.toString('hex'))
  })

  describe('fromJSON', () => {
    it('full node', (done) => {
      PeerId.create({bits: 1024}, (err, id) => {
        expect(err).to.not.exist

        PeerId.createFromJSON(id.toJSON(), (err, other) => {
          expect(err).to.not.exist
          expect(
            id.toB58String()
          ).to.equal(
            other.toB58String()
          )
          expect(
            id.privKey.bytes
          ).to.deep.equal(
            other.privKey.bytes
          )
          expect(
            id.pubKey.bytes
          ).to.deep.equal(
            other.pubKey.bytes
          )
          done()
        })
      })
    })

    it('only id', (done) => {
      crypto.generateKeyPair('RSA', 1024, (err, key) => {
        expect(err).to.not.exist
        key.public.hash((err, digest) => {
          expect(err).to.not.exist

          const id = PeerId.createFromBytes(digest)
          expect(id.privKey).to.not.exist
          expect(id.pubKey).to.not.exist

          PeerId.createFromJSON(id.toJSON(), (err, other) => {
            expect(err).to.not.exist
            expect(
              id.toB58String()
            ).to.equal(
              other.toB58String()
            )
            done()
          })
        })
      })
    })

    it('go interop', (done) => {
      PeerId.createFromJSON(goId, (err, id) => {
        expect(err).to.not.exist
        id.privKey.public.hash((err, digest) => {
          expect(err).to.not.exist
          expect(
            mh.toB58String(digest)
          ).to.be.eql(
            goId.id
          )
          done()
        })
      })
    })
  })

  describe('throws on inconsistent data', () => {
    let k1, k2, k3
    before((done) => {
      parallel([
        (cb) => crypto.generateKeyPair('RSA', 1024, cb),
        (cb) => crypto.generateKeyPair('RSA', 1024, cb),
        (cb) => crypto.generateKeyPair('RSA', 1024, cb)
      ], (err, keys) => {
        if (err) {
          return done(err)
        }

        k1 = keys[0]
        k2 = keys[1]
        k3 = keys[2]
        done()
      })
    })

    it('missmatch private - public key', (done) => {
      k1.public.hash((err, digest) => {
        expect(err).to.not.exist
        expect(
          () => new PeerId(digest, k1, k2.public)
        ).to.throw(
            /inconsistent arguments/
        )
        done()
      })
    })

    it('missmatch id - private - public key', (done) => {
      k1.public.hash((err, digest) => {
        expect(err).to.not.exist
        expect(
          () => new PeerId(digest, k1, k3.public)
        ).to.throw(
            /inconsistent arguments/
        )
        done()
      })
    })

    it('invalid id', () => {
      expect(
        () => new PeerId('hello world')
      ).to.throw(
        /invalid id/
      )
    })
  })
})
