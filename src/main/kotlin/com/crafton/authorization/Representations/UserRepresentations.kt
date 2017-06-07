package com.crafton.authorization.Representations

import com.fasterxml.jackson.annotation.JsonProperty

data class Authorization(
        val permissions: Set<Permission>
)

data class Permission(
        val scopes: Set<String>,
        @JsonProperty("resource_set_id")
        val resourceSetId: String,
        @JsonProperty("resource_set_name")
        val resourceSetName: String
)
