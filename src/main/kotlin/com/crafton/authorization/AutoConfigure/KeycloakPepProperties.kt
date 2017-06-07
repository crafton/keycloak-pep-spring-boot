package com.crafton.authorization.AutoConfigure

import org.hibernate.validator.constraints.NotBlank
import org.springframework.boot.context.properties.ConfigurationProperties


@ConfigurationProperties("QutKeycloakPep")
data class KeycloakPepProperties(
        @NotBlank
        val realmUrl: String,
        @NotBlank
        val tokenUrl: String,
        @NotBlank
        val policyEnforcementFilename: String,
        @NotBlank
        val clientId: String
)