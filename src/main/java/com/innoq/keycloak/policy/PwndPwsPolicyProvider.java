package com.innoq.keycloak.policy;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import static com.innoq.keycloak.policy.PwndPwsPolicyProviderFactory.ID;

final class PwndPwsPolicyProvider implements PasswordPolicyProvider {

    private static final String ERROR_MESSAGE = "invalidPasswordTooMuchBreachesMessage";

    private final PwndPwsClient client = new PwndPwsClient();
    private final KeycloakContext context;

    public PwndPwsPolicyProvider(KeycloakContext context) {
        this.context = context;
    }

    @Override
    public PolicyError validate(String username, String password) {
        final int allowedBreaches = context.getRealm()
                .getPasswordPolicy()
                .getPolicyConfig(ID);
        final int actualBreaches =
                this.client.numberOfBreachesIncluding(password);
        return actualBreaches > allowedBreaches
                ? new PolicyError(ERROR_MESSAGE, actualBreaches, allowedBreaches)
                : null;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return validate(null, password);
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, 1);
    }

    @Override
    public void close() {
    }
}
