package info.vividcode.oauth.protocol

import info.vividcode.oauth.ParamList
import info.vividcode.oauth.key
import info.vividcode.oauth.value

object ParameterTransmission {

    /**
     * See : [OAuth 1.0 Specification - 3.5.1 Authorization Header](https://tools.ietf.org/html/rfc5849#section-3.5.1)
     */
    fun getAuthorizationHeaderString(protocolParams: ParamList, realm: String): String {
        val sb = StringBuilder()
        sb.append("OAuth realm=\"").append(realm).append('"')
        val pp = protocolParams.stream()
                .map { p -> PercentEncode.encode(p.key) + "=\"" + PercentEncode.encode(p.value) + '"' }
                .reduce({ s1, s2 -> s1 + ", " + s2 }).orElse("")
        return "OAuth " + pp
    }

}
