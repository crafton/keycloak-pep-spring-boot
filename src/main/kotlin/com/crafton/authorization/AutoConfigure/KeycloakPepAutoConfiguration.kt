package com.crafton.authorization.AutoConfigure

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.crafton.authorization.AuthorizingAgent
import com.crafton.authorization.PolicyEnforcer
import com.crafton.authorization.RealmConfig
import com.crafton.authorization.Representations.PepConfig
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate
import java.io.File

@Configuration
@ConditionalOnWebApplication
@EnableConfigurationProperties(KeycloakPepProperties::class)
class KeycloakPepAutoConfiguration(val pepProperties: KeycloakPepProperties) {

    val mapper = jacksonObjectMapper()

    @Bean
    fun pepConfig(): PepConfig {
        val pepConfig: PepConfig = mapper.readValue(KeycloakPepAutoConfiguration::class.java.getResource("/${pepProperties.policyEnforcementFilename}").readText())

        val duplicateNames: List<String> = findDuplicateEndpointNames(pepConfig.endpoints)
        if(duplicateNames.isNotEmpty()){
            throw IllegalArgumentException("Duplicate resource names not allowed. Detected the following: ${duplicateNames.joinToString(",")}")
        }

        return pepConfig
    }

    @Bean
    fun realmConfig(): RealmConfig {
        val restTemplate = RestTemplate()
        val realmInfoAsJsonString : String = restTemplate.getForObject(pepProperties.realmUrl, String::class.java)
        return mapper.readValue(realmInfoAsJsonString)
    }

    @Bean
    @ConditionalOnMissingBean
    fun restTemplate(): RestTemplate = RestTemplate()

    @Bean
    @ConditionalOnBean(*arrayOf(RealmConfig::class, RestTemplate::class, KeycloakPepProperties::class))
    fun authorizingAgent(): AuthorizingAgent = AuthorizingAgent(realmConfig(), restTemplate(), pepProperties)

    @Bean
    @ConditionalOnBean(*arrayOf(PepConfig::class, AuthorizingAgent::class))
    fun policyEnforcer(): PolicyEnforcer = PolicyEnforcer(pepConfig(), authorizingAgent())
}