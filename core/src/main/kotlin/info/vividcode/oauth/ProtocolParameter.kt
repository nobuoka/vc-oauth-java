package info.vividcode.oauth

import java.time.Instant

abstract class ProtocolParameter<out T>(val name: Name<*>, val value: T) {

    abstract class Name<E : ProtocolParameter<*>>(private val string: String) {
        override fun toString(): String = string
    }

    class ConsumerKey(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<ConsumerKey>("oauth_consumer_key")
    }
    class Token(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<Token>("oauth_token")
    }
    class Signature(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<Signature>("oauth_signature")
    }
    sealed class SignatureMethod(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<SignatureMethod>("oauth_signature_method")
        object Plaintext : SignatureMethod("PLAINTEXT")
        object HmacSha1 : SignatureMethod("HMAC-SHA1")
    }
    class Nonce(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<Nonce>("oauth_nonce")
    }
    class Timestamp(value: Instant) : ProtocolParameter<Long>(Companion, value.epochSecond) {
        companion object : ProtocolParameter.Name<Timestamp>("oauth_timestamp")
    }
    class Version() : ProtocolParameter<String>(Companion, "1.0") {
        companion object : ProtocolParameter.Name<Version>("oauth_version")
    }
    class Verifier(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<Verifier>("oauth_verifier")
    }
    class Callback(value: String) : ProtocolParameter<String>(Companion, value) {
        companion object : ProtocolParameter.Name<Callback>("oauth_callback")
    }

}
