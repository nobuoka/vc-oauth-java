/*
Copyright 2014, 2017 NOBUOKA Yu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package info.vividcode.oauth

import info.vividcode.oauth.protocol.PercentEncode
import info.vividcode.oauth.protocol.Signatures
import info.vividcode.oauth.protocol.UrlEncoded
import java.net.URL
import java.security.SecureRandom
import java.time.Clock
import java.util.*

class OAuth(env: Env) {

    interface Env : NextIntEnv, ClockEnv

    companion object {
        @JvmStatic
        val DEFAULT: OAuth = OAuth(object : Env {
            override val nextInt: (Int) -> Int = SecureRandom.getInstanceStrong()::nextInt
            override val clock: Clock = Clock.systemDefaultZone()
        })
    }

    private val nonceGenerator = OAuthNonceGenerator(env)
    private val clock = env.clock

    fun generateProtocolParametersSigningWithHmacSha1(
            httpRequest: HttpRequest, clientCredentials: OAuthCredentials, temporaryOrTokenCredentials: OAuthCredentials?,
            additionalProtocolParameters: List<ProtocolParameter<*>>? = null
    ): ProtocolParameterSet {
        val protocolParams = OAuthProtocolParameters.createProtocolParametersExcludingSignature(
                clientCredentials.identifier,
                temporaryOrTokenCredentials?.identifier,
                OAuthProtocolParameters.Options.HmcSha1Signing(nonceGenerator.generateNonceString(), clock.instant()),
                additionalProtocolParameters
        )
        val signatureBaseString = generateSignatureBaseString(httpRequest, protocolParams)
        val secrets = PercentEncode.encode(clientCredentials.sharedSecret) +
                '&' + PercentEncode.encode(temporaryOrTokenCredentials?.sharedSecret ?: "")
        val signature = when (protocolParams.get(ProtocolParameter.SignatureMethod)) {
            is ProtocolParameter.SignatureMethod.HmacSha1 -> Signatures.makeSignatureWithHmacSha1(secrets, signatureBaseString)
            is ProtocolParameter.SignatureMethod.Plaintext -> secrets
            null -> throw RuntimeException("No signature method specified")
        }
        return ProtocolParameterSet.Builder().add(protocolParams).add(ProtocolParameter.Signature(signature)).build()
    }

    fun generateSignatureBaseString(httpRequest: HttpRequest, protocolParams: ProtocolParameterSet): String =
            generateSignatureBaseString(httpRequest, protocolParams.map { Param(it.name.toString(), it.value.toString()) })

    fun generateSignatureBaseString(httpRequest: HttpRequest, protocolParams: ParamList): String {
        val sb = StringBuilder()

        // 1.  The HTTP request method in uppercase.  For example: "HEAD", "GET", "POST", etc.
        //     If the request uses a custom HTTP method, it MUST be encoded (Section 3.6).
        val upperHttpRequestMethod = httpRequest.method.toUpperCase(Locale.US)
        sb.append(PercentEncode.encode(upperHttpRequestMethod))
        // 2.  An "&" character (ASCII code 38).
        sb.append('&')
        // 3.  The base string URI from Section 3.4.1.2, after being encoded (Section 3.6).
        val baseStringUri = generateBaseStringUri(httpRequest.url)
        sb.append(PercentEncode.encode(baseStringUri))
        // 4.  An "&" character (ASCII code 38).
        sb.append('&')
        // 5.  The request parameters as normalized in Section 3.4.1.3.2, after being encoded (Section 3.6).
        val encodedReqParams =
                (protocolParams.map { Param(PercentEncode.encode(it.key), PercentEncode.encode(it.value)) }) +
                        collectPercentEncodedRequestParameters(httpRequest.url, httpRequest.wwwFormUrlEncodedRequestBody)
        val normalizedRequestParameters = normalizePercentEncodedParameters(encodedReqParams)
        sb.append(PercentEncode.encode(normalizedRequestParameters))

        return sb.toString()
    }

    fun generateBaseStringUri(url: URL): String {
        val sb = StringBuilder()

        // The scheme, authority, and path of the request resource URI [RFC3986] are included by constructing
        // an "http" or "https" URI representing the request resource (without the query or fragment) as follows:
        //     1.  The scheme and host MUST be in lowercase.
        //     2.  The host and port values MUST match the content of the HTTP request "Host" header field.
        //     3.  The port MUST be included if it is not the default port for the scheme, and MUST be excluded
        //         if it is the default.  Specifically, the port MUST be excluded when making an HTTP request [RFC2616]
        //         to port 80 or when making an HTTPS request [RFC2818] to port 443.
        //         All other non-default port numbers MUST be included.
        val scheme = url.protocol.toLowerCase(Locale.US)
        sb.append(scheme).append("://")
        val host = url.host.toLowerCase(Locale.US)
        sb.append(host)
        val port = url.port
        if (port != -1) {
            val isHttpDefaultPort = "http" == scheme && port == 80
            val isHttpsDefaultPort = "https" == scheme && port == 443
            if (!isHttpDefaultPort && !isHttpsDefaultPort) {
                sb.append(':').append(port)
            }
        }
        // TODO: is it okay if path is empty string?
        sb.append(url.path)

        return sb.toString()
    }

    /**
     * [RFC 5849 section 3.4.1.3](https://tools.ietf.org/html/rfc5849#section-3.4.1.3)
     *
     * @param url Request URL, query parameters of which are used.
     * @param requestBody Request body or null. If it is specified, it must be an "application/x-www-form-urlencoded" string.
     * @return Percent-encoded parameters.
     */
    fun collectPercentEncodedRequestParameters(url: URL, requestBody: String?): ParamList {
        val pp = mutableListOf<Param>()

        // o  The query component of the HTTP request URI as defined by
        //    [RFC3986], Section 3.4.  The query component is parsed into a list
        //    of name/value pairs by treating it as an
        //    "application/x-www-form-urlencoded" string, separating the names
        //    and values and decoding them as defined by
        //    [W3C.REC-html40-19980424], Section 17.13.4.
        val queryString = url.query
        if (queryString != null) {
            collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(queryString, pp)
        }

        // o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
        //    present.  The header's content is parsed into a list of name/value
        //    pairs excluding the "realm" parameter if present.  The parameter
        //    values are decoded as defined by Section 3.5.1.

        // Currently this is not supported.

        // o  The HTTP request entity-body, but only if all of the following
        //    conditions are met:
        //
        //    *  The entity-body is single-part.
        //
        //    *  The entity-body follows the encoding requirements of the
        //       "application/x-www-form-urlencoded" content-type as defined by
        //       [W3C.REC-html40-19980424].
        //
        //    *  The HTTP request entity-header includes the "Content-Type"
        //       header field set to "application/x-www-form-urlencoded".
        //
        //    The entity-body is parsed into a list of decoded name/value pairs
        //    as described in [W3C.REC-html40-19980424], Section 17.13.4.
        if (requestBody != null) {
            collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(requestBody, pp)
        }

        // The "oauth_signature" parameter MUST be excluded from the signature
        // base string if present.  Parameters not explicitly included in the
        // request MUST be excluded from the signature base string (e.g., the
        // "oauth_version" parameter when omitted).

        return pp
    }

    // TODO : 空文字列の時の処理。
    fun collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(s: String, p: MutableList<Param>) {
        val pairs = s.split("&".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        for (pair in pairs) {
            val encKv = pair.split("=".toRegex(), 2).toTypedArray()
            if ("oauth_signature" == encKv[0]) continue
            val key = UrlEncoded.decode(encKv[0])
            val `val` = UrlEncoded.decode(if (encKv.size == 1) "" else encKv[1])
            p.add(Param(PercentEncode.encode(key), PercentEncode.encode(`val`)))
        }
    }

    fun normalizePercentEncodedParameters(percentEncodedParams: ParamList): String {
        Collections.sort(percentEncodedParams, ParamComparator)
        val sb = StringBuilder()
        for (p in percentEncodedParams) {
            if (sb.length != 0) sb.append('&')
            sb.append(p.key).append('=').append(p.value)
        }
        return sb.toString()
    }

}
