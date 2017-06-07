package com.crafton.authorization.Representations


data class PepConfig(
        val endpoints: Set<PepEndpoint>
)

data class PepEndpoint(
        val name: String,
        val paths: Set<String>,
        val entitlements: Set<PepEntitlement>
)

data class PepEntitlement(
        val methods: Set<String>,
        val scopes: Set<String>
)