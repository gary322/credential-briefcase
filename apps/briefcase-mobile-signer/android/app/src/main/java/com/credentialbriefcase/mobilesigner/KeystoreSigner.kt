package com.credentialbriefcase.mobilesigner

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

object KeystoreSigner {
    private const val alias = "com.credentialbriefcase.mobile-signer.p256"

    fun loadOrCreateKeyPair(): KeyPair {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (ks.containsAlias(alias)) {
            val priv = ks.getKey(alias, null) as PrivateKey
            val pub = ks.getCertificate(alias).publicKey as ECPublicKey
            return KeyPair(pub, priv)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    fun publicKeySec1Bytes(pub: ECPublicKey): ByteArray {
        val point = pub.w
        val x = bigIntToFixed32(point.affineX)
        val y = bigIntToFixed32(point.affineY)
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(x, 0, out, 1, 32)
        System.arraycopy(y, 0, out, 33, 32)
        return out
    }

    fun sign(priv: PrivateKey, message: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(priv)
        sig.update(message)
        return sig.sign()
    }

    private fun bigIntToFixed32(x: BigInteger): ByteArray {
        val bytes = x.toByteArray()
        // BigInteger.toByteArray() is signed big-endian; strip any sign byte and left-pad.
        val unsigned = if (bytes.size == 33 && bytes[0].toInt() == 0) bytes.copyOfRange(1, 33) else bytes
        if (unsigned.size > 32) {
            throw IllegalArgumentException("coordinate too large")
        }
        val out = ByteArray(32)
        System.arraycopy(unsigned, 0, out, 32 - unsigned.size, unsigned.size)
        return out
    }
}

