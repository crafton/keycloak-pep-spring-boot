package com.crafton.authorization

import com.crafton.authorization.Representations.PepConfig
import com.crafton.authorization.Representations.Permission
import org.springframework.stereotype.Service

@Service
class PolicyEnforcer(val pepConfig: PepConfig, val authorizingAgent: AuthorizingAgent) {

    /**
     * Determine if a user is authorized to access a particular resource
     *
     * @param accessToken
     * @param path
     * @param httpMethod
     * @return boolean
     */
    fun isUserAuthorized(accessToken: String, path: String, httpMethod: String): Boolean {

        val pepResourceSetName = getPepResourceSetName(path) ?: return false

        val authorization = authorizingAgent.getAuthorization(accessToken) ?: return false

        val permissions = authorization.permissions
        if (permissions.isEmpty()) {
            return false
        }

        val applicableScopes = getApplicableScopes(pepResourceSetName, permissions)?: return false

        val pepEndpoint = pepConfig.endpoints.find { it.name == pepResourceSetName }?: return false

        for((methods, scopes) in pepEndpoint.entitlements){
            if(doSetsIntersect(scopes, applicableScopes) && methods.contains(httpMethod)){
                return true
            }
        }

        return false
    }

    /**
     * Check if at least one element in set b is contained in set a
     *
     * @param a
     * @param b
     * @return
     */
    private fun doSetsIntersect(a: Set<String>, b: Set<String>): Boolean = a.intersect(b).isNotEmpty()

    /**
     * Retrieve all scopes from the authorization claim associated with a given resource Set
     *
     * @param pepResourceSetName
     * @param permissions
     * @return
     */
    private fun getApplicableScopes(pepResourceSetName: String, permissions: Set<Permission>): Set<String>? {
        return permissions.find { it.resourceSetName == pepResourceSetName }?.scopes
    }

    /**
     * Given a user requested path, retrieve the associated resource set name.
     *
     * @param requestedPath
     * @return Resource set name as String
     */
    private fun getPepResourceSetName(requestedPath: String): String? {
        for ((name, paths) in pepConfig.endpoints) {
            paths.filter { isMatched(it, requestedPath) }
                    .forEach { return name }
        }
        return null
    }

    /**
     * Check to see if the client requested path matches one of the configured pep paths
     *
     * @param protectedResourcePath
     * @param resourcePathRequested
     * @return Boolean
     */
    private fun isMatched(protectedResourcePath: String, resourcePathRequested: String): Boolean {

        if (!resourcePathRequested.contains("/") || !protectedResourcePath.contains("/")) {
            return false
        }

        if (resourcePathRequested.endsWith("*")) {
            return false
        }

        if (protectedResourcePath == resourcePathRequested) {
            return true
        }

        if (resourcePathRequested == "/") {
            return false
        }

        if (protectedResourcePath.endsWith("*")) {
            val protectedResourcePathParams = protectedResourcePath.split("/")
            val resourcePathRequestedParams = resourcePathRequested.split("/")

            if (resourcePathRequestedParams.size < protectedResourcePathParams.size) {
                return false
            }

            val protectedWithoutWildCard = protectedResourcePathParams.dropLast(1)
            val requestedPathToWildCard = resourcePathRequestedParams.subList(0, protectedWithoutWildCard.size)

            if (protectedWithoutWildCard == requestedPathToWildCard) {
                return true
            }

        }

        return false
    }
}