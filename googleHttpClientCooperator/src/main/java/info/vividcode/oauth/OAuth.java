/*
Copyright 2014 NOBUOKA Yu

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

package info.vividcode.oauth;

import info.vividcode.util.oauth.OAuthEncoder;
import info.vividcode.util.oauth.OAuthRequestHelper.Param;
import info.vividcode.util.oauth.OAuthRequestHelper.ParamComparator;
import info.vividcode.util.oauth.OAuthRequestHelper.ParamList;

import java.net.URL;
import java.util.Collections;
import java.util.Locale;

public class OAuth {

    public static String generateSignatureBaseString(
            String method, URL url, ParamList protocolParams, String requestBody) {
        StringBuilder sb = new StringBuilder();

        // 1.  The HTTP request method in uppercase.  For example: "HEAD",
        //     "GET", "POST", etc.  If the request uses a custom HTTP method, it
        //     MUST be encoded (Section 3.6).
        method = method.toUpperCase(Locale.US);
        sb.append(OAuthEncoder.encode(method));
        // 2.  An "&" character (ASCII code 38).
        sb.append('&');
        // 3.  The base string URI from Section 3.4.1.2, after being encoded
        //     (Section 3.6).
        String baseStringUri = generateBaseStringUri(url);
        sb.append(OAuthEncoder.encode(baseStringUri));
        // 4.  An "&" character (ASCII code 38).
        sb.append('&');
        // 5.  The request parameters as normalized in Section 3.4.1.3.2, after
        //     being encoded (Section 3.6).
        ParamList encodedReqParams = new ParamList();
        if (protocolParams != null) {
            for (Param p : protocolParams) {
                String encKey = OAuthEncoder.encode(p.getKey());
                String encVal = OAuthEncoder.encode(p.getValue());
                encodedReqParams.add(new Param(encKey, encVal));
            }
        }
        encodedReqParams.addAll(collectPercentEncodedRequestParameters(url, requestBody));
        String normalizedRequestParameters = normalizePercentEncodedParameters(encodedReqParams);
        sb.append(OAuthEncoder.encode(normalizedRequestParameters));

        return sb.toString();
    }

    public static String generateBaseStringUri(URL url) {
        StringBuilder sb = new StringBuilder();

        // The scheme, authority, and path of the request resource URI [RFC3986]
        // are included by constructing an "http" or "https" URI representing
        // the request resource (without the query or fragment) as follows:
        //     1.  The scheme and host MUST be in lowercase.
        //     2.  The host and port values MUST match the content of the HTTP
        //         request "Host" header field.
        //     3.  The port MUST be included if it is not the default port for the
        //         scheme, and MUST be excluded if it is the default.  Specifically,
        //         the port MUST be excluded when making an HTTP request [RFC2616]
        //         to port 80 or when making an HTTPS request [RFC2818] to port 443.
        //         All other non-default port numbers MUST be included.
        String scheme = url.getProtocol().toLowerCase(Locale.US);
        sb.append(scheme).append("://");
        String host = url.getHost().toLowerCase(Locale.US);
        sb.append(host);
        int port = url.getPort();
        if (port != -1) {
            boolean isHttpDefaultPort = ("http".equals(scheme) && port == 80);
            boolean isHttpsDefaultPort = ("https".equals(scheme) && port == 443);
            if (!isHttpDefaultPort && !isHttpsDefaultPort) {
                sb.append(':').append(port);
            }
        }
        // TODO: is it okay if path is empty string?
        sb.append(url.getPath());

        return sb.toString();
    }

    /**
     * <a href="https://tools.ietf.org/html/rfc5849#section-3.4.1.3">RFC 5849 section 3.4.1.3</a>
     *
     * @param url Request URL, query parameters of which are used.
     * @param requestBody Request body or null. If it is specified, it must be an "application/x-www-form-urlencoded" string.
     * @return Percent-encoded parameters.
     */
    public static ParamList collectPercentEncodedRequestParameters(URL url, String requestBody) {
        ParamList pp = new ParamList();

        // o  The query component of the HTTP request URI as defined by
        //    [RFC3986], Section 3.4.  The query component is parsed into a list
        //    of name/value pairs by treating it as an
        //    "application/x-www-form-urlencoded" string, separating the names
        //    and values and decoding them as defined by
        //    [W3C.REC-html40-19980424], Section 17.13.4.
        String queryString = url.getQuery();
        if (queryString != null) {
            collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(queryString, pp);
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
            collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(queryString, pp);
        }

        // The "oauth_signature" parameter MUST be excluded from the signature
        // base string if present.  Parameters not explicitly included in the
        // request MUST be excluded from the signature base string (e.g., the
        // "oauth_version" parameter when omitted).

        return pp;
    }

    public static void collectPercentEncodedParametersFromUrlEncodedStringIntoParamList(String s, ParamList p) {
        String[] pairs = s.split("&");
        for (String pair : pairs) {
            String[] encKv = pair.split("=", 2);
            if ("oauth_signature".equals(encKv[0])) continue;
            byte[] key = UrlEncoded.decode(encKv[0]);
            byte[] val = UrlEncoded.decode(encKv.length == 1 ? "" : encKv[1]);
            p.add(new Param(OAuthEncoder.encode(key), OAuthEncoder.encode(val)));
        }
    }

    public static String normalizePercentEncodedParameters(ParamList percentEncodedParams) {
        Collections.sort(percentEncodedParams, ParamComparator.getInstance());
        StringBuilder sb = new StringBuilder();
        for (Param p : percentEncodedParams) {
            if (sb.length() != 0) sb.append('&');
            sb.append(p.getKey()).append('=').append(p.getValue());
        }
        return sb.toString();
    }

}
