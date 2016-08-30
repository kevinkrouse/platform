package org.labkey.api.issues;


import org.labkey.api.data.Container;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.security.User;

import java.util.List;

public class IssuesListDefService
{
    private static Service INSTANCE;

    public static Service get()
    {
        return INSTANCE;
    }

    public static void setInstance(Service impl)
    {
        INSTANCE = impl;
    }

    public interface Service
    {
        /**
         * Register a provider that will be used as the "Kind" for a new issue list definition creation.
         * @param provider the provider that defines the domain for the issue list definition.
         */
        void registerIssuesListDefProvider(IssuesListDefProvider provider);

        /**
         * Get the full set of registered issue list definition providers.
         * @return List of IssuesListDefProvider
         */
        List<IssuesListDefProvider> getIssuesListDefProviders();

        /**
         * Get the set of registered issue list definition providers that are enabled based on the given container (most likely
         * based on the set of active modules for that container).
         * @param container the container to check for enabled providers
         * @return
         */
        List<IssuesListDefProvider> getEnabledIssuesListDefProviders(Container container);

        /**
         * Get a registered issue list definition provider based on the provider's name.
         * @param providerName the name to check for in the registered list of providers
         * @return IssuesListDefProvider
         */
        IssuesListDefProvider getIssuesListDefProvider(String providerName);

        /**
         * Get the Domain for a specific issue list definition based on the issue list definition name.
         * @param issueDefName the name of the issue list definition to look for
         * @param container the container to look in
         * @param user the user who made the request
         * @return Domain
         */
        Domain getDomainFromIssueDefName(String issueDefName, Container container, User user);

        /**
         * Register a provider that will add text links to the issue details header link display.
         * @param provider the provider that will determine which links to add based on a given IssueListDef
         */
        void registerIssueDetailHeaderLinkProvider(IssueDetailHeaderLinkProvider provider);

        /**
         * Returns the list of registered providers which can add links to the issue detail header link listing.
         * @return the list of registered providers
         */
        List<IssueDetailHeaderLinkProvider> getIssueDetailHeaderLinkProviders();
    }
}

