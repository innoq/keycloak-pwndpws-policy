package com.innoq.keycloak.policy;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

import static org.keycloak.policy.PasswordPolicyProvider.INT_CONFIG_TYPE;

public final class PwndPwsPolicyProviderFactory implements PasswordPolicyProviderFactory {

    static final String ID = "pwndpws";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new PwndPwsPolicyProvider(session.getContext());
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getDisplayName() {
        return "Pwned Passwords";
    }

    @Override
    public String getConfigType() {
        return INT_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return "1";
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public void close() {
    }
}
