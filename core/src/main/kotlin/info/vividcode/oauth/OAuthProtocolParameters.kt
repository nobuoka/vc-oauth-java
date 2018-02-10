package info.vividcode.oauth

import java.time.Instant

object OAuthProtocolParameters {

    sealed class Options {
        data class PlaintextSigning(val nonce: String?, val timestamp: Instant?) : Options()
        data class HmcSha1Signing(val nonce: String, val timestamp: Instant) : Options()
    }

    fun createProtocolParametersExcludingSignature(
            clientIdentifier: String,
            temporaryOrTokenIdentifier: String?,
            options: Options,
            additionalProtocolParameters: List<ProtocolParameter<*>>?
    ) = ProtocolParameterSet.Builder().apply {
        add(ProtocolParameter.ConsumerKey(clientIdentifier))
        when (options) {
            is Options.PlaintextSigning -> {
                add(ProtocolParameter.SignatureMethod.Plaintext)
                options.nonce?.let { add(ProtocolParameter.Nonce(it)) }
                options.timestamp?.let { add(ProtocolParameter.Timestamp(it)) }
            }
            is Options.HmcSha1Signing -> {
                add(ProtocolParameter.SignatureMethod.HmacSha1)
                add(ProtocolParameter.Nonce(options.nonce))
                add(ProtocolParameter.Timestamp(options.timestamp))
            }
        }
        temporaryOrTokenIdentifier?.let { add(ProtocolParameter.Token(it)) }
        additionalProtocolParameters?.let { add(it) }
    }.build()

    fun createProtocolParametersExcludingSignatureForTemporaryCredentialRequest(
            clientCredentials: OAuthCredentials,
            options: Options,
            callbackUrl: String? = null,
            additionalProtocolParameters: List<ProtocolParameter<*>>? = null
    ): ProtocolParameterSet = createProtocolParametersExcludingSignature(
            clientCredentials.identifier, null,
            options,
            mutableListOf<ProtocolParameter<*>>().apply {
                additionalProtocolParameters?.let { addAll(it) }
                callbackUrl?.let { add(ProtocolParameter.Callback(it)) }
            }
    )

    fun createProtocolParametersForTokenCredentialRequest(
            clientCredentials: OAuthCredentials,
            temporaryCredentials: OAuthCredentials,
            options: Options,
            verifier: String,
            additionalProtocolParameters: List<ProtocolParameter<*>>? = null
    ): ProtocolParameterSet = createProtocolParametersExcludingSignature(
            clientCredentials.identifier, temporaryCredentials.identifier,
            options,
            mutableListOf<ProtocolParameter<*>>().apply {
                additionalProtocolParameters?.let { addAll(it) }
                add(ProtocolParameter.Verifier(verifier))
            }
    )

}
