package com.crafton.authorization

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.RSAKeyProvider
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.crafton.authorization.AutoConfigure.KeycloakPepProperties
import com.crafton.authorization.Representations.Authorization
import org.slf4j.LoggerFactory
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Service
class AuthorizingAgent(val realmConfig: RealmConfig, val restTemplate: RestTemplate, val pepProperties: KeycloakPepProperties) {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    fun getAuthorization(accessToken: String): Authorization? = getRptAuthorization(accessToken)

    /**
     * Given an access token, query the Keycloak entitlements API and retrieve the RPT
     */
    private fun getRptAuthorization(accessToken: String): Authorization? {
        val headers = HttpHeaders()
        headers.add("Authorization", "Bearer $accessToken")
        val entity = HttpEntity(null, headers)

        val tokenUrl: String = "${pepProperties.tokenUrl}${pepProperties.clientId}"
        val rpt: String = restTemplate.exchange(tokenUrl, HttpMethod.GET, entity, String::class.java).body
        val mapper = jacksonObjectMapper()
        val rptMap: Map<String, String> = mapper.readValue(rpt)
        val rptString = rptMap["rpt"] ?: return null
        val decodedRPT = verifyRpt(rptString) ?: return null
        val claim = decodedRPT.getClaim("authorization") ?: return null

        return mapper.readValue(claim.asString())
    }

    private fun verifyRpt(token: String): DecodedJWT? = verifyToken(token)

    private fun verifyAccessToken(token: String): DecodedJWT? = verifyToken(token)

    /**
     * Decode a JWT and verify its signature.
     *
     * @param token
     * @return DecodedJWT or null
     */
    private fun verifyToken(token: String): DecodedJWT? {
        try {
            val publicBytes = Base64.getDecoder().decode(realmConfig.publicKey)
            val keySpec = X509EncodedKeySpec(publicBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(keySpec)

            val rsaPublicKey = publicKey as RSAPublicKey
            val keyProvider = object : RSAKeyProvider {
                override fun getPrivateKeyId(): String? {
                    return null
                }

                override fun getPrivateKey(): RSAPrivateKey? {
                    return null
                }

                override fun getPublicKeyById(keyId: String?): RSAPublicKey? {
                    return rsaPublicKey
                }
            }

            val algorithm = Algorithm.RSA256(keyProvider)
            val jwtVerifier = JWT.require(algorithm)
                    .build()
            return jwtVerifier.verify(token)
        } catch (e: Exception) {
            logger.warn("Token verification failed with: ${e.message}")
            return null
        }
    }
}