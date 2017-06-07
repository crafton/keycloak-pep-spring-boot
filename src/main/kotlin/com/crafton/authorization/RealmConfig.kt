package com.crafton.authorization

import com.fasterxml.jackson.annotation.JsonProperty


class RealmConfig (
        val realm: String,
        @JsonProperty("public_key")
        val publicKey: String,
        @JsonProperty("token-service")
        val tokenService: String,
        @JsonProperty("account-service")
        val accountService: String,
        @JsonProperty("admin-api")
        val adminApi: String,
        @JsonProperty("tokens-not-before")
        val tokensNotBefore: String
)