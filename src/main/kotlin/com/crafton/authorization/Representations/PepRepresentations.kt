package com.crafton.authorization.Representations


data class PepConfig(
        val endpoints: Set<PepEndpoint>
)

data class PepEndpoint(
        val name: String,
        val path: String,
        val entitlements: Set<PepEntitlement>
)

data class PepEntitlement(
        val method: String,
        val scopes: Set<String>
)