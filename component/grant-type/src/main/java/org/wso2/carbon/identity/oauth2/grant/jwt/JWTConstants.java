/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */
package org.wso2.carbon.identity.oauth2.grant.jwt;

public class JWTConstants {

    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "assertion";
    public static final String JWKS_URI = "jwksUri";
    public static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";
    // Expiry time of the jwt token
    public static final String EXPIRY_TIME = "EXPIRY_TIME_JWT";

    public static final String PROP_ENABLE_IAT_VALIDATION = "OAuth.JWTGrant.EnableIATValidation";
    public static final String PROP_IAT_VALIDITY_PERIOD = "OAuth.JWTGrant.IATValidityPeriod";
    public static final String PROP_ENABLE_JWT_CACHE = "OAuth.JWTGrant.EnableJWTCache";
    public static final int DEFAULT_IAT_VALIDITY_PERIOD = 30;
    public static final String PROP_REGISTERED_JWT = "OAuth.JWTGrant.RegisteredClaim";

    /**
     * When true (default), jwt-bearer success persists selected assertion claims into the local
     * user store ({@code UM_USER_ATTRIBUTE}) via {@code setUserClaimValues}.
     */
    public static final String PROP_PERSIST_USER_ATTRIBUTES = "OAuth.JWTGrant.PersistUserAttributes";

    /**
     * When true (default), only fill empty local attributes; do not overwrite existing values.
     */
    public static final String PROP_PERSIST_FILL_EMPTY_ONLY = "OAuth.JWTGrant.PersistUserAttributes.FillEmptyOnly";

    /**
     * When true (default), sync JWT roles into the local user store (UM hybrid roles)
     * so client_credentials can authorize system scopes such as {@code apim:subscribe}.
     */
    public static final String PROP_PERSIST_USER_ROLES = "OAuth.JWTGrant.PersistUserRoles";

    /**
     * When true (default), if the JWT has no usable roles, still ensure {@code Internal/subscriber}
     * for federated shadow users (same intent as former FederatedUserSyncUtil).
     */
    public static final String PROP_PERSIST_DEFAULT_SUBSCRIBER_ROLE =
            "OAuth.JWTGrant.PersistUserRoles.DefaultSubscriberRole";

    public static final String LOCAL_CLAIM_EMAIL = "http://wso2.org/claims/emailaddress";
    public static final String LOCAL_CLAIM_DISPLAY_NAME = "http://wso2.org/claims/displayname";
    public static final String LOCAL_CLAIM_NICKNAME = "http://wso2.org/claims/nickname";
    public static final String LOCAL_CLAIM_MOBILE = "http://wso2.org/claims/mobile";

    public static final String ROLE_INTERNAL_SUBSCRIBER = "Internal/subscriber";
    public static final String LOCAL_CLAIM_ROLE = "http://wso2.org/claims/role";
    public static final String LOCAL_CLAIM_ROLES = "http://wso2.org/claims/roles";
}
