# Contiki-EOS
EOS blockchain communication module for Smart Contract Sensors powered by Contiki-NG OS.

## Structure

### Big Picture

The future of IoT is now.  A global network of sensors delivering secured, auditable and permissiond data to a decentralized platform. We can take on GAFAM.  Anything is possible.

The big picture beings to look like this.  On each device, we'd like to have a local lightweight nodeos module running as a Contiki process.  The local device application firmware communicates to the nodeos module - submitting sensor data, polling for updates, etc.  It sort of sits at the top layer of the network stack. The nodeos module creates signed actions, queues then submits transactions to the broader EOS network and its smart contracts. The nodeos module also maintains relevant network state such as the peer list and chain state data for forming valid transactions. 

Now, the local nodeos module won't look anything like that which exists today - it is something designed from the ground up for resource constrained IoT.  It communicates not over HTTP/TCP but over CoAP/UDP and it uses not JSON but a serialized binary representation.  This means that other nodeos peers must also have such a CoAP/UDP binary endpoint enabled.  So, a nodeos plugin to support this ecosystem must be developed and deployed and incorporated by a number of EOS nodes fairly close the core, if not the core itself.  Perhaps the entire network switches away from HTTP/TCP to adopt this IoT-focused architecture.

### First Steps

The first thing we need to do is create wallet and install an EOS-compatible signing engine into the Contiki framework.

#### Wallet

Many people think a cryptocurrency wallet stores their tokens. Contrary to popular belief, tokens are stored on the blockchain itself, visible to anyone and everyone.  So what's in the wallet?  Simply put, the wallet stores your ability to spend those tokens.  In EOS and other blockchains (like Bitcoin), this ability is provided by the "secret key".  In EOS specifically, the power to move and allocate tokens is given by having control of these three pieces of information:
* Private key
* Corresponding public key
* Corresponding account name

EOS and many other cryptosystems rely on ECDSA (Elliptic Curve Digital Signing Algorithm) techniques to secure transactions and prove ownership.  The specific elliptic curve used is called secp256k1. In this scheme, the private key is 256 bits (32 bytes), the public compressed-format key is 33 bytes (32 bytes plus 1-byte header), and the EOS account name is generally 12 characters.  The device's wallet then need only contain this information, which could be provisioned specifically for that device.

#### Transaction Signing Engine

As said above the EOS transactions are signed using ECDSA techniques and the secp256k1 curve.  A few options we have here are as follows:
* Hardware ECDSA (preferred)
* Software ECDSA with TinyDTLS
* Software ECDSA with a purpose built secp256r1 cryptolib like [this](https://github.com/bitcoin-core/secp256k1 )


