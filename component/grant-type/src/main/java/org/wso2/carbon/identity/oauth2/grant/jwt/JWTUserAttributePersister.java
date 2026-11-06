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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Persist selected JWT assertion claims into the local JDBC user store
 * ({@code UM_USER} / {@code UM_USER_ATTRIBUTE}) during jwt-bearer grant,
 * and sync JWT roles into hybrid roles so {@code client_credentials} can
 * authorize system scopes such as {@code apim:subscribe}.
 * <p>
 * Failures are logged and do not fail token issuance.
 */
public class JWTUserAttributePersister {

    private static final Log log = LogFactory.getLog(JWTUserAttributePersister.class);

    private static final String[] PERSISTED_LOCAL_CLAIMS = new String[]{
            JWTConstants.LOCAL_CLAIM_EMAIL,
            JWTConstants.LOCAL_CLAIM_DISPLAY_NAME,
            JWTConstants.LOCAL_CLAIM_NICKNAME,
            JWTConstants.LOCAL_CLAIM_MOBILE
    };

    private static final String[] ROLE_CLAIM_KEYS = new String[]{
            "roles",
            "groups",
            "role",
            JWTConstants.LOCAL_CLAIM_ROLE,
            JWTConstants.LOCAL_CLAIM_ROLES
    };

    private JWTUserAttributePersister() {
    }

    /**
     * @param subject          JWT {@code sub} (typically Keycloak user id)
     * @param customClaims     Full JWT claim set map
     * @param identityProvider Resolved IdP for claim dialect mapping
     * @param tenantDomain     Tenant domain
     * @param tokReqMsgCtx     Token request context (for ClaimsUtil)
     * @param customClaimMap   Pre-extracted non-registered claims (short names / URIs)
     */
    public static void persist(String subject, Map<String, Object> customClaims, IdentityProvider identityProvider,
                               String tenantDomain, OAuthTokenReqMessageContext tokReqMsgCtx,
                               Map<String, String> customClaimMap) {

        boolean persistEnabled = isPersistEnabled();
        boolean fillEmptyOnly = isFillEmptyOnly();
        boolean persistRoles = isPersistRolesEnabled();
        String idpName = identityProvider != null ? identityProvider.getIdentityProviderName() : "null";
        log.debug("JWT attr persist enter: enabled=" + persistEnabled + ", fillEmptyOnly=" + fillEmptyOnly
                + ", persistRoles=" + persistRoles
                + ", subject=" + subject + ", tenant=" + tenantDomain + ", idp=" + idpName
                + ", assertionClaimKeys=" + (customClaims != null ? customClaims.keySet() : "null")
                + ", customClaimKeys=" + (customClaimMap != null ? customClaimMap.keySet() : "null"));

        if (!persistEnabled) {
            log.debug("JWT attr persist skipped: OAuth.JWTGrant.PersistUserAttributes is false");
            return;
        }
        if (StringUtils.isBlank(subject)) {
            log.debug("JWT attr persist skipped: blank subject");
            return;
        }
        if (MapUtils.isEmpty(customClaimMap) && MapUtils.isEmpty(customClaims)) {
            log.debug("JWT attr persist skipped: empty customClaimMap and customClaims");
            return;
        }

        try {
            Map<String, String> safeClaimMap = customClaimMap != null ? customClaimMap : Collections.emptyMap();
            Map<String, String> localClaims = resolveLocalClaims(safeClaimMap, identityProvider, tenantDomain,
                    tokReqMsgCtx);
            Map<String, String> toWrite = filterPersistedClaims(localClaims);
            List<String> rolesToSync = persistRoles
                    ? resolveRolesToSync(customClaims, safeClaimMap, identityProvider)
                    : Collections.emptyList();

            log.debug("JWT attr persist mapped: subject=" + subject
                    + ", localClaimKeys=" + localClaims.keySet()
                    + ", toWriteKeys=" + toWrite.keySet()
                    + ", toWritePreview=" + previewClaims(toWrite)
                    + ", rolesToSync=" + rolesToSync);

            if (MapUtils.isEmpty(toWrite) && rolesToSync.isEmpty()) {
                log.debug("JWT attr persist skipped: no attributes and no roles to sync for subject=" + subject);
                return;
            }

            String username = MultitenantUtils.getTenantAwareUsername(subject.trim());
            UserRealm realm = IdentityTenantUtil.getRealm(tenantDomain, null);
            if (realm == null) {
                log.warn("Cannot persist JWT user attributes: realm is null for tenant=" + tenantDomain
                        + ", username=" + username);
                return;
            }
            UserStoreManager userStoreManager = realm.getUserStoreManager();
            if (userStoreManager == null) {
                log.warn("Cannot persist JWT user attributes: UserStoreManager is null for tenant=" + tenantDomain
                        + ", username=" + username);
                return;
            }

            boolean existing = userStoreManager.isExistingUser(username);
            log.debug("JWT attr persist userStore: username=" + username + ", tenant=" + tenantDomain
                    + ", existingUser=" + existing);
            if (!existing) {
                ensureLocalUser(userStoreManager, username, toWrite);
            }
            // Always set claims after create (or when user already exists). Covers:
            // 1) FederatedUserSync* bare UM_USER race leaving empty attributes
            // 2) addUser succeeding without claim dialect write
            // 3) second jwt-bearer fill-empty path
            if (MapUtils.isNotEmpty(toWrite)) {
                updateAttributes(userStoreManager, username, toWrite);
            }
            if (!rolesToSync.isEmpty()) {
                syncLocalRoles(userStoreManager, username, rolesToSync);
            }
            // Read-back to confirm JDBC claim write actually landed (helps distinguish mapping vs store issues).
            try {
                Map<String, String> after = userStoreManager.getUserClaimValues(username, PERSISTED_LOCAL_CLAIMS, null);
                String[] afterRoles = userStoreManager.getRoleListOfUser(username);
                log.debug("JWT attr persist read-back: username=" + username
                        + ", claims=" + previewClaims(after)
                        + ", roles=" + Arrays.toString(afterRoles));
            } catch (Exception readBackEx) {
                log.warn("JWT attr persist read-back failed for username=" + username + ": "
                        + readBackEx.getMessage());
            }
        } catch (Exception e) {
            // Never fail jwt-bearer token issuance because of attribute/role sync.
            log.warn("Failed to persist JWT user attributes/roles for subject=" + subject + ", tenant=" + tenantDomain
                    + ": " + e.getClass().getName() + ": " + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("JWT user attribute persist error", e);
            }
        }
    }

    private static boolean isPersistEnabled() {
        String configured = IdentityUtil.getProperty(JWTConstants.PROP_PERSIST_USER_ATTRIBUTES);
        // Default: enabled for this customized grant.
        return configured == null || Boolean.parseBoolean(configured.trim());
    }

    private static boolean isFillEmptyOnly() {
        String configured = IdentityUtil.getProperty(JWTConstants.PROP_PERSIST_FILL_EMPTY_ONLY);
        return configured == null || Boolean.parseBoolean(configured.trim());
    }

    private static boolean isPersistRolesEnabled() {
        String configured = IdentityUtil.getProperty(JWTConstants.PROP_PERSIST_USER_ROLES);
        return configured == null || Boolean.parseBoolean(configured.trim());
    }

    private static boolean isDefaultSubscriberRoleEnabled() {
        String configured = IdentityUtil.getProperty(JWTConstants.PROP_PERSIST_DEFAULT_SUBSCRIBER_ROLE);
        return configured == null || Boolean.parseBoolean(configured.trim());
    }

    private static Map<String, String> resolveLocalClaims(Map<String, String> customClaimMap,
                                                          IdentityProvider identityProvider,
                                                          String tenantDomain,
                                                          OAuthTokenReqMessageContext tokReqMsgCtx) {

        Map<String, String> localClaims = new HashMap<>();
        // 1) IdP claim mappings (remote to local URI) when available.
        if (identityProvider != null && tokReqMsgCtx != null && MapUtils.isNotEmpty(customClaimMap)) {
            try {
                Map<String, String> mapped = ClaimsUtil.handleClaimMapping(identityProvider, customClaimMap,
                        tenantDomain, tokReqMsgCtx);
                if (MapUtils.isNotEmpty(mapped)) {
                    localClaims.putAll(mapped);
                    log.debug("JWT attr persist IdP claim mapping ok: mappedKeys=" + mapped.keySet());
                } else {
                    log.debug("JWT attr persist IdP claim mapping returned empty; will use OIDC fallback");
                }
            } catch (Exception e) {
                log.debug("JWT attr persist IdP claim mapping failed; falling back to OIDC short-name map: "
                        + e.getClass().getName() + ": " + e.getMessage());
            }
        } else {
            log.debug("JWT attr persist skip IdP mapping: idpNull=" + (identityProvider == null)
                    + ", tokCtxNull=" + (tokReqMsgCtx == null)
                    + ", claimMapEmpty=" + MapUtils.isEmpty(customClaimMap)
                    + "; will use OIDC fallback");
        }
        // 2) Fallback: common OIDC / Keycloak claim names to local claim URIs.
        applyFallbackOidcMappings(customClaimMap, localClaims);
        return localClaims;
    }

    private static void applyFallbackOidcMappings(Map<String, String> source, Map<String, String> target) {
        if (source == null) {
            return;
        }
        putIfAbsent(target, JWTConstants.LOCAL_CLAIM_EMAIL, firstNonBlank(source,
                "email", JWTConstants.LOCAL_CLAIM_EMAIL, "http://wso2.org/claims/emailaddress"));
        putIfAbsent(target, JWTConstants.LOCAL_CLAIM_DISPLAY_NAME, firstNonBlank(source,
                "name", "displayName", "display_name", JWTConstants.LOCAL_CLAIM_DISPLAY_NAME));
        putIfAbsent(target, JWTConstants.LOCAL_CLAIM_NICKNAME, firstNonBlank(source,
                "preferred_username", "nickname", "nickName", "username", JWTConstants.LOCAL_CLAIM_NICKNAME));
        putIfAbsent(target, JWTConstants.LOCAL_CLAIM_MOBILE, firstNonBlank(source,
                "phoneNumber", "phone_number", "mobile", "phone", JWTConstants.LOCAL_CLAIM_MOBILE));
    }

    private static Map<String, String> filterPersistedClaims(Map<String, String> localClaims) {
        Map<String, String> filtered = new HashMap<>();
        for (String uri : PERSISTED_LOCAL_CLAIMS) {
            String value = localClaims.get(uri);
            if (StringUtils.isNotBlank(value)) {
                filtered.put(uri, value.trim());
            }
        }
        return filtered;
    }

    private static void ensureLocalUser(UserStoreManager userStoreManager, String username,
                                        Map<String, String> claims) throws UserStoreException {

        // Federated shadow account: random credential; users authenticate via jwt-bearer, not password.
        // Must match typical JDBC userstore PasswordJavaRegEx: ^[\S]{5,30}$ (UUID with dashes is 36 chars and fails).
        String credential = buildFederatedShadowPassword();
        Map<String, String> safeClaims = claims != null ? claims : Collections.emptyMap();
        String[] initialRoles = isDefaultSubscriberRoleEnabled()
                ? new String[]{JWTConstants.ROLE_INTERNAL_SUBSCRIBER} : null;
        log.debug("JWT attr persist creating local user: username=" + username
                + ", claimKeys=" + safeClaims.keySet() + ", claimPreview=" + previewClaims(safeClaims)
                + ", initialRoles=" + Arrays.toString(initialRoles));
        try {
            userStoreManager.addUser(username, credential, initialRoles, safeClaims, null);
            log.debug("JWT attr persist created local user ok: username=" + username);
        } catch (UserStoreException e) {
            // FederatedUserSyncHandler may INSERT a bare UM_USER on PRE_ADD_USER before claims are written.
            // addUser then fails with USER_ALREADY_EXISTS and would leave um_user_attribute empty;
            // fall back to setUserClaimValues so the first jwt-bearer still fills nickname/phone/email.
            if (isUserAlreadyExists(e)) {
                log.warn("JWT attr persist addUser raced with federated sync (user already exists), "
                        + "falling back to setUserClaimValues: username=" + username
                        + ", err=" + e.getMessage());
                if (MapUtils.isNotEmpty(safeClaims)) {
                    updateAttributes(userStoreManager, username, safeClaims);
                }
                return;
            }
            throw e;
        }
    }

    /**
     * Password for local shadow users. Length 5..30, no whitespace matches default
     * {@code PasswordJavaRegEx}=^[\S]{5,30}$.
     */
    private static String buildFederatedShadowPassword() {
        // 32 hex chars without dashes; trim to 30 to satisfy upper bound.
        String hex = UUID.randomUUID().toString().replace("-", "");
        return hex.length() <= 30 ? hex : hex.substring(0, 30);
    }

    private static boolean isUserAlreadyExists(UserStoreException e) {
        if (e == null) {
            return false;
        }
        String message = e.getMessage();
        if (message != null && (message.contains("USER_ALREADY_EXISTS")
                || message.toLowerCase(Locale.ENGLISH).contains("already exists"))) {
            return true;
        }
        Throwable cause = e.getCause();
        if (cause != null && cause != e && cause.getMessage() != null) {
            String causeMsg = cause.getMessage();
            return causeMsg.contains("USER_ALREADY_EXISTS")
                    || causeMsg.toLowerCase(Locale.ENGLISH).contains("already exists");
        }
        return false;
    }

    private static void updateAttributes(UserStoreManager userStoreManager, String username,
                                         Map<String, String> claims) throws UserStoreException {

        Map<String, String> toSet = claims;
        if (isFillEmptyOnly()) {
            Map<String, String> existing = userStoreManager.getUserClaimValues(username, PERSISTED_LOCAL_CLAIMS, null);
            log.debug("JWT attr persist fillEmptyOnly: username=" + username
                    + ", existingPreview=" + previewClaims(existing)
                    + ", incomingKeys=" + claims.keySet());
            toSet = new HashMap<>();
            for (Map.Entry<String, String> entry : claims.entrySet()) {
                String current = existing != null ? existing.get(entry.getKey()) : null;
                if (StringUtils.isBlank(current)) {
                    toSet.put(entry.getKey(), entry.getValue());
                }
            }
        }
        if (MapUtils.isEmpty(toSet)) {
            log.debug("JWT attr persist skipped write: nothing to set for username=" + username
                    + " (fillEmptyOnly=" + isFillEmptyOnly() + ", attributes already populated or empty incoming)");
            return;
        }
        log.debug("JWT attr persist setUserClaimValues: username=" + username
                + ", claimKeys=" + toSet.keySet() + ", claimPreview=" + previewClaims(toSet));
        userStoreManager.setUserClaimValues(username, toSet, null);
        log.debug("JWT attr persist setUserClaimValues ok: username=" + username);
    }

    /**
     * Resolve local roles from JWT claims (+ IdP role mappings). Never removes existing local roles.
     */
    private static List<String> resolveRolesToSync(Map<String, Object> customClaims,
                                                   Map<String, String> customClaimMap,
                                                   IdentityProvider identityProvider) {

        LinkedHashSet<String> remoteRoles = new LinkedHashSet<>();
        collectRolesFromClaimMap(remoteRoles, customClaimMap, identityProvider);
        collectRolesFromClaimObjects(remoteRoles, customClaims, identityProvider);

        LinkedHashSet<String> localRoles = new LinkedHashSet<>();
        for (String remoteRole : remoteRoles) {
            List<String> mapped = mapRemoteRoleToLocal(identityProvider, remoteRole);
            if (mapped.isEmpty()) {
                continue;
            }
            localRoles.addAll(mapped);
        }

        // Always ensure Internal/subscriber when enabled. KC JWTs usually carry realm_access.roles
        // (offline_access / uma_authorization / ...). Those make localRoles non-empty but are not
        // WSO2 hybrid roles, so the old "default only if empty" path never assigned subscriber.
        if (isDefaultSubscriberRoleEnabled()) {
            int mappedBeforeDefault = localRoles.size();
            localRoles.add(JWTConstants.ROLE_INTERNAL_SUBSCRIBER);
            log.debug("JWT role sync: ensuring " + JWTConstants.ROLE_INTERNAL_SUBSCRIBER
                    + " (mappedLocalRolesBeforeDefault=" + mappedBeforeDefault
                    + ", remoteRoles=" + remoteRoles + ")");
        }
        return new ArrayList<>(localRoles);
    }

    private static void collectRolesFromClaimMap(Set<String> target, Map<String, String> customClaimMap,
                                                 IdentityProvider identityProvider) {

        if (MapUtils.isEmpty(customClaimMap)) {
            return;
        }
        for (String key : ROLE_CLAIM_KEYS) {
            addRolesFromDelimitedString(target, firstNonBlank(customClaimMap, key));
        }
        if (identityProvider != null && identityProvider.getClaimConfig() != null
                && StringUtils.isNotBlank(identityProvider.getClaimConfig().getRoleClaimURI())) {
            addRolesFromDelimitedString(target,
                    firstNonBlank(customClaimMap, identityProvider.getClaimConfig().getRoleClaimURI()));
        }
    }

    @SuppressWarnings("unchecked")
    private static void collectRolesFromClaimObjects(Set<String> target, Map<String, Object> customClaims,
                                                     IdentityProvider identityProvider) {

        if (MapUtils.isEmpty(customClaims)) {
            return;
        }
        for (String key : ROLE_CLAIM_KEYS) {
            addRolesFromObject(target, customClaims.get(key));
            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                    addRolesFromObject(target, entry.getValue());
                }
            }
        }
        if (identityProvider != null && identityProvider.getClaimConfig() != null
                && StringUtils.isNotBlank(identityProvider.getClaimConfig().getRoleClaimURI())) {
            addRolesFromObject(target, customClaims.get(identityProvider.getClaimConfig().getRoleClaimURI()));
        }
        // Keycloak default shape: realm_access.roles
        Object realmAccess = customClaims.get("realm_access");
        if (realmAccess instanceof Map) {
            addRolesFromObject(target, ((Map<?, ?>) realmAccess).get("roles"));
        }
        // Keycloak client roles: resource_access.<client>.roles
        Object resourceAccess = customClaims.get("resource_access");
        if (resourceAccess instanceof Map) {
            for (Object clientEntry : ((Map<?, ?>) resourceAccess).values()) {
                if (clientEntry instanceof Map) {
                    addRolesFromObject(target, ((Map<?, ?>) clientEntry).get("roles"));
                }
            }
        }
    }

    private static List<String> mapRemoteRoleToLocal(IdentityProvider identityProvider, String remoteRole) {

        String normalized = normalizeRoleToken(remoteRole);
        if (StringUtils.isBlank(normalized)) {
            return Collections.emptyList();
        }
        // Keycloak / remote may send bare "subscriber"; WSO2 hybrid role requires Internal/ prefix.
        if ("subscriber".equalsIgnoreCase(normalized)
                || JWTConstants.ROLE_INTERNAL_SUBSCRIBER.equalsIgnoreCase(normalized)) {
            return Collections.singletonList(JWTConstants.ROLE_INTERNAL_SUBSCRIBER);
        }
        if (identityProvider == null
                || StringUtils.equalsIgnoreCase(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME,
                identityProvider.getIdentityProviderName())) {
            return Collections.singletonList(normalized);
        }

        PermissionsAndRoleConfig permissionAndRoleConfig = identityProvider.getPermissionAndRoleConfig();
        if (permissionAndRoleConfig == null || ArrayUtils.isEmpty(permissionAndRoleConfig.getRoleMappings())) {
            if (OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
                return Collections.emptyList();
            }
            return Collections.singletonList(normalized);
        }

        for (RoleMapping roleMapping : permissionAndRoleConfig.getRoleMappings()) {
            if (roleMapping == null || roleMapping.getRemoteRole() == null || roleMapping.getLocalRole() == null) {
                continue;
            }
            if (!roleMapping.getRemoteRole().equals(normalized)
                    && !roleMapping.getRemoteRole().equalsIgnoreCase(normalized)) {
                continue;
            }
            // Avoid UserCoreConstants (not imported by this OSGi bundle); default domain sep is "/".
            String updatedLocalRole = StringUtils.isEmpty(roleMapping.getLocalRole().getUserStoreId())
                    ? roleMapping.getLocalRole().getLocalRoleName()
                    : roleMapping.getLocalRole().getUserStoreId() + "/"
                    + roleMapping.getLocalRole().getLocalRoleName();
            if (StringUtils.isNotBlank(updatedLocalRole)) {
                return Collections.singletonList(updatedLocalRole.trim());
            }
        }
        if (OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
            return Collections.emptyList();
        }
        return Collections.singletonList(normalized);
    }

    private static void syncLocalRoles(UserStoreManager userStoreManager, String username, List<String> desiredRoles)
            throws UserStoreException {

        String[] existingRoles = userStoreManager.getRoleListOfUser(username);
        Set<String> existing = new HashSet<>();
        if (existingRoles != null) {
            for (String role : existingRoles) {
                if (StringUtils.isNotBlank(role)) {
                    existing.add(role.trim().toLowerCase(Locale.ENGLISH));
                }
            }
        }

        List<String> toAdd = new ArrayList<>();
        for (String role : desiredRoles) {
            if (StringUtils.isBlank(role) || existing.contains(role.trim().toLowerCase(Locale.ENGLISH))) {
                continue;
            }
            if (!userStoreManager.isExistingRole(role)) {
                log.warn("JWT role sync skip unknown local role for username=" + username + ", role=" + role);
                continue;
            }
            toAdd.add(role);
        }

        if (toAdd.isEmpty()) {
            log.info("JWT role sync nothing to add for username=" + username
                    + ", existing=" + Arrays.toString(existingRoles) + ", desired=" + desiredRoles);
            return;
        }

        log.info("JWT role sync assigning roles for username=" + username + ", roles=" + toAdd);
        userStoreManager.updateRoleListOfUser(username, null, toAdd.toArray(new String[0]));
        log.info("JWT role sync updateRoleListOfUser ok: username=" + username + ", added=" + toAdd);
    }

    private static void addRolesFromDelimitedString(Set<String> target, String raw) {
        if (StringUtils.isBlank(raw)) {
            return;
        }
        String cleaned = normalizeRoleToken(raw);
        if (StringUtils.isBlank(cleaned)) {
            return;
        }
        String separator = FrameworkUtils.getMultiAttributeSeparator();
        if (cleaned.contains(separator)) {
            for (String part : cleaned.split(java.util.regex.Pattern.quote(separator))) {
                String role = normalizeRoleToken(part);
                if (StringUtils.isNotBlank(role)) {
                    target.add(role);
                }
            }
            return;
        }
        // Also split common JSON-array leftovers joined by comma.
        if (cleaned.contains(",")) {
            for (String part : cleaned.split(",")) {
                String role = normalizeRoleToken(part);
                if (StringUtils.isNotBlank(role)) {
                    target.add(role);
                }
            }
            return;
        }
        target.add(cleaned);
    }

    private static void addRolesFromObject(Set<String> target, Object value) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            addRolesFromDelimitedString(target, (String) value);
            return;
        }
        if (value instanceof Collection) {
            for (Object item : (Collection<?>) value) {
                addRolesFromObject(target, item);
            }
            return;
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                addRolesFromObject(target, Array.get(value, i));
            }
            return;
        }
        addRolesFromDelimitedString(target, value.toString());
    }

    private static String normalizeRoleToken(String raw) {
        if (raw == null) {
            return null;
        }
        String cleaned = raw.replace("\\/", "/")
                .replace("[", "")
                .replace("]", "")
                .replace("\"", "")
                .trim();
        return StringUtils.isBlank(cleaned) ? null : cleaned;
    }

    /**
     * Log-safe preview: show keys and masked/truncated values (avoid dumping full PII).
     */
    private static String previewClaims(Map<String, String> claims) {
        if (claims == null || claims.isEmpty()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : claims.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            String key = e.getKey();
            String shortKey = key != null && key.contains("/")
                    ? key.substring(key.lastIndexOf('/') + 1) : key;
            sb.append(shortKey).append('=').append(maskValue(e.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    private static String maskValue(String value) {
        if (value == null) {
            return "null";
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return "<blank>";
        }
        if (trimmed.length() <= 2) {
            return "**(len=" + trimmed.length() + ")";
        }
        if (trimmed.length() <= 6) {
            return trimmed.charAt(0) + "***" + trimmed.charAt(trimmed.length() - 1)
                    + "(len=" + trimmed.length() + ")";
        }
        return trimmed.substring(0, 2) + "***" + trimmed.substring(trimmed.length() - 2)
                + "(len=" + trimmed.length() + ")";
    }

    private static void putIfAbsent(Map<String, String> target, String key, String value) {
        if (StringUtils.isBlank(value)) {
            return;
        }
        if (StringUtils.isBlank(target.get(key))) {
            target.put(key, value.trim());
        }
    }

    private static String firstNonBlank(Map<String, String> source, String... keys) {
        if (source == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = source.get(key);
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
            // Case-insensitive key match (KC mappers may vary casing).
            for (Map.Entry<String, String> entry : source.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)
                        && StringUtils.isNotBlank(entry.getValue())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }
}
