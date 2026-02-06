package com.credentialbriefcase.mobilesigner

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

// Minimal Noise implementation for a single handshake pattern:
//
//   Noise_NNpsk0_25519_ChaChaPoly_SHA256
//
// This matches `docs/PAIRING.md` and `briefcased`'s `snow` usage.
class NoiseNNpsk0Initiator(psk: ByteArray) {
    private val psk: ByteArray
    private var symmetric = SymmetricState("Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    private var e: X25519PrivateKeyParameters? = null

    init {
        require(psk.size == 32) { "psk must be 32 bytes" }
        this.psk = psk.copyOf()
    }

    fun writeMessage1(payload: ByteArray = ByteArray(0)): ByteArray {
        // message1: psk, e
        symmetric.mixKeyAndHash(psk)

        val rnd = SecureRandom()
        val eph = X25519PrivateKeyParameters(rnd)
        e = eph
        val ePub = eph.generatePublicKey().encoded
        symmetric.mixHash(ePub)
        // PSK mode: MixKey(e.public_key) after MixHash(e.public_key)
        symmetric.mixKey(ePub)

        val ciphertext = symmetric.encryptAndHash(payload)
        return ePub + ciphertext
    }

    fun readMessage2(message: ByteArray): ByteArray {
        // message2: e, ee
        if (message.size < 32 + 16) throw IllegalArgumentException("invalid message2")
        val eph = e ?: throw IllegalStateException("message1 not written")

        val rePubBytes = message.copyOfRange(0, 32)
        val rest = message.copyOfRange(32, message.size)

        symmetric.mixHash(rePubBytes)
        symmetric.mixKey(rePubBytes) // PSK mode.

        val re = X25519PublicKeyParameters(rePubBytes, 0)
        val dh = ByteArray(32)
        val agree = X25519Agreement()
        agree.init(eph)
        agree.calculateAgreement(re, dh, 0)
        symmetric.mixKey(dh)

        return symmetric.decryptAndHash(rest)
    }

    private class CipherState {
        private var key: ByteArray? = null
        private var nonce: Long = 0L

        fun initializeKey(keyBytes: ByteArray?) {
            key = keyBytes?.copyOf()
            nonce = 0L
        }

        private fun nonceBytes(): ByteArray {
            // 96-bit nonce = 4 zero bytes || little_endian(nonce64)
            val out = ByteArray(12)
            var n = nonce
            for (i in 0 until 8) {
                out[4 + i] = (n and 0xff).toByte()
                n = n ushr 8
            }
            return out
        }

        fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
            val k = key ?: return plaintext
            val nonceBytes = nonceBytes()

            val aead = ChaCha20Poly1305()
            aead.init(true, AEADParameters(KeyParameter(k), 128, nonceBytes, ad))

            val out = ByteArray(aead.getOutputSize(plaintext.size))
            var len = aead.processBytes(plaintext, 0, plaintext.size, out, 0)
            len += aead.doFinal(out, len)
            nonce += 1
            return out.copyOf(len)
        }

        fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
            val k = key ?: return ciphertext
            val nonceBytes = nonceBytes()

            val aead = ChaCha20Poly1305()
            aead.init(false, AEADParameters(KeyParameter(k), 128, nonceBytes, ad))

            val out = ByteArray(aead.getOutputSize(ciphertext.size))
            try {
                var len = aead.processBytes(ciphertext, 0, ciphertext.size, out, 0)
                len += aead.doFinal(out, len)
                nonce += 1
                return out.copyOf(len)
            } catch (e: InvalidCipherTextException) {
                throw IllegalArgumentException("decrypt failed", e)
            }
        }
    }

    private class SymmetricState(protocolName: String) {
        private var cipher = CipherState()
        private var ck: ByteArray
        private var h: ByteArray

        init {
            val pn = protocolName.toByteArray(Charsets.UTF_8)
            h = if (pn.size <= 32) {
                pn + ByteArray(32 - pn.size)
            } else {
                sha256(pn)
            }
            ck = h.copyOf()
            cipher.initializeKey(null)
        }

        fun mixHash(data: ByteArray) {
            h = sha256(h + data)
        }

        fun mixKey(ikm: ByteArray) {
            val outs = hkdf(ck, ikm, 2)
            ck = outs[0]
            cipher.initializeKey(outs[1])
        }

        fun mixKeyAndHash(ikm: ByteArray) {
            val outs = hkdf(ck, ikm, 3)
            ck = outs[0]
            mixHash(outs[1])
            cipher.initializeKey(outs[2])
        }

        fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val ciphertext = cipher.encryptWithAd(h, plaintext)
            mixHash(ciphertext)
            return ciphertext
        }

        fun decryptAndHash(ciphertext: ByteArray): ByteArray {
            val plaintext = cipher.decryptWithAd(h, ciphertext)
            mixHash(ciphertext)
            return plaintext
        }

        companion object {
            private fun sha256(data: ByteArray): ByteArray {
                val md = MessageDigest.getInstance("SHA-256")
                return md.digest(data)
            }

            private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(key, "HmacSHA256"))
                return mac.doFinal(data)
            }

            private fun hkdf(chainingKey: ByteArray, ikm: ByteArray, n: Int): List<ByteArray> {
                val tempKey = hmacSha256(chainingKey, ikm)
                val output1 = hmacSha256(tempKey, byteArrayOf(0x01))
                val output2 = hmacSha256(tempKey, output1 + byteArrayOf(0x02))
                if (n == 2) return listOf(output1, output2)
                val output3 = hmacSha256(tempKey, output2 + byteArrayOf(0x03))
                return listOf(output1, output2, output3)
            }
        }
    }
}

