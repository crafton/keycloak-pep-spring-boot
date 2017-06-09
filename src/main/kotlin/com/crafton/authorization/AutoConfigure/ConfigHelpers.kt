package com.crafton.authorization.AutoConfigure

import com.crafton.authorization.Representations.PepEndpoint

/**
 * Find the duplicate resource names in the Pep file
 *
 */
fun findDuplicateEndpointNames(pepEndpoints: Set<PepEndpoint>): List<String> {
    val allEndpoints = pepEndpoints.toList()
    val distinctEndpoints = pepEndpoints.distinctBy { it.name }

    val duplicateEndpointNames = mutableListOf<String>()
    if (allEndpoints.size > distinctEndpoints.size) {
        val duplicateEndpoints: List<PepEndpoint> = allEndpoints.minus(distinctEndpoints)
        duplicateEndpoints.forEach { duplicateEndpointNames.add(it.name) }
    }

    return duplicateEndpointNames
}
