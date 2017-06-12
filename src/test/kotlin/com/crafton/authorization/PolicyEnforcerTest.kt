package com.crafton.authorization

import com.crafton.authorization.AutoConfigure.findDuplicateEndpointNames
import com.crafton.authorization.Representations.Authorization
import com.crafton.authorization.Representations.PepConfig
import com.fasterxml.jackson.module.kotlin.MissingKotlinParameterException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nhaarman.mockito_kotlin.doReturn
import com.nhaarman.mockito_kotlin.mock
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on
import org.mockito.Matchers
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

object PolicyEnforcerTest : Spek({

    val mapper = jacksonObjectMapper()
    val pepConfig: PepConfig = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/pep.json").readText())

    val duplicates = findDuplicateEndpointNames(pepConfig.endpoints)
    if (duplicates.isNotEmpty()) {
        throw IllegalArgumentException("Found the following duplicate endpoints: ${duplicates.joinToString(",")}")
    }

    given("a Policy Enforcer, make an authorization decision based on path and method") {

        val authorization: Authorization = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/authorization.json").readText())
        val userAuthorization = mock<AuthorizingAgent> {
            on { getAuthorization(Matchers.anyString()) } doReturn authorization
        }
        val policyEnforcer = PolicyEnforcer(pepConfig, userAuthorization)

        on("isUserAuthorized is called with any string, a '/people/home' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/home", "GET")

            it("should return true") {
                assertTrue(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/people' as path and an http '/people' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/people/home' as path and an http 'POST' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/home", "POST")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '*' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "*", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/*' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/*", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/applications/type' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/applications/type", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/applications/type/name' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/applications/type/name", "GET")

            it("should return true") {
                assertTrue(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/people/car' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/car", "GET")

            it("should return true") {
                assertTrue(decision)
            }
        }

        on("isUserAuthorized is called with any string, a '/drones/people' as path and an http 'GET' method") {
            val decision = policyEnforcer.isUserAuthorized("an access token", "/drones/people", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

    }

    given("a policy enforcer, certain token contents must result in authorization being denied") {

        on("permissions are empty") {
            val authorization: Authorization = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/authorization-noperms.json").readText())
            val userAuthorization = mock<AuthorizingAgent> {
                on { getAuthorization(Matchers.anyString()) } doReturn authorization
            }
            val policyEnforcer = PolicyEnforcer(pepConfig, userAuthorization)
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/home", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("permissions are null") {
            assertFailsWith(MissingKotlinParameterException::class) {
                val authorization: Authorization = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/authorization-invalid.json").readText())
            }
        }

        on("authorization claims have no matching scopes") {
            val authorization: Authorization = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/authorization-nomatchingscopes.json").readText())
            val userAuthorization = mock<AuthorizingAgent> {
                on { getAuthorization(Matchers.anyString()) } doReturn authorization
            }
            val policyEnforcer = PolicyEnforcer(pepConfig, userAuthorization)
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/home", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }

        on("authorization claim has no matching resource names") {
            val authorization: Authorization = mapper.readValue(PolicyEnforcerTest::class.java.getResource("/authorization-nomatchingresourcename.json").readText())
            val userAuthorization = mock<AuthorizingAgent> {
                on { getAuthorization(Matchers.anyString()) } doReturn authorization
            }
            val policyEnforcer = PolicyEnforcer(pepConfig, userAuthorization)
            val decision = policyEnforcer.isUserAuthorized("an access token", "/people/home", "GET")

            it("should return false") {
                assertFalse(decision)
            }
        }
    }

})