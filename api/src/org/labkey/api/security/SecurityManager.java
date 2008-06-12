/*
 * Copyright (c) 2005-2008 Fred Hutchinson Cancer Research Center
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.labkey.api.security;

import junit.framework.Test;
import junit.framework.TestSuite;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.labkey.api.data.*;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.util.*;
import org.labkey.api.util.emailTemplate.EmailTemplate;
import org.labkey.api.util.emailTemplate.EmailTemplateService;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.ViewContext;
import org.labkey.api.wiki.WikiService;
import org.labkey.common.util.Pair;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Note should consider implementing a Tomcat REALM, but we've tried to avoid
 * being tomcat specific.
 */

public class SecurityManager
{
    private static Logger _log = Logger.getLogger(SecurityManager.class);
    private static CoreSchema core = CoreSchema.getInstance();
    private static final String TERMS_OF_USE_WIKI_NAME = "_termsOfUse";
    private static List<ViewFactory> _viewFactories = new ArrayList<ViewFactory>();
    private static final String GROUP_CACHE_PREFIX = "Groups/MetaData=";

    static {
        EmailTemplateService.get().registerTemplate(RegistrationEmailTemplate.class);
        EmailTemplateService.get().registerTemplate(RegistrationAdminEmailTemplate.class);
        EmailTemplateService.get().registerTemplate(PasswordResetEmailTemplate.class);
        EmailTemplateService.get().registerTemplate(PasswordResetAdminEmailTemplate.class);
    }

    public enum PermissionSet
    {
        ADMIN("Admin (all permissions)", ACL.PERM_ALLOWALL),
        EDITOR("Editor", ACL.PERM_READ | ACL.PERM_DELETE | ACL.PERM_UPDATE | ACL.PERM_INSERT),
        AUTHOR("Author", ACL.PERM_READ | ACL.PERM_DELETEOWN | ACL.PERM_UPDATEOWN | ACL.PERM_INSERT),
        READER("Reader", ACL.PERM_READ),
        RESTRICTED_READER("Restricted Reader", ACL.PERM_READOWN),
        SUBMITTER("Submitter", ACL.PERM_INSERT),
        NO_PERMISSIONS("No Permissions", 0);

        private static List<Pair<Integer, String>> _allPerms;
        static {
            _allPerms = new ArrayList<Pair<Integer, String>>();
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_READ, "READ"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_INSERT, "INSERT"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_UPDATE, "UPDATE"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_DELETE, "DELETE"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_READOWN, "READ-OWN"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_UPDATEOWN, "UPDATE-OWN"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_DELETEOWN, "DELETE-OWN"));
            _allPerms.add(new Pair<Integer, String>(ACL.PERM_ADMIN, "ADMIN"));
        }
        private int _permissions;
        private String _label;
        private PermissionSet(String label, int permissions)
        {
            // the following must be true for normalization to work:
            assert ACL.PERM_READOWN == ACL.PERM_READ << 4;
            assert ACL.PERM_UPDATEOWN == ACL.PERM_UPDATE << 4;
            assert ACL.PERM_DELETEOWN == ACL.PERM_DELETE << 4;
            _permissions = permissions;
            _label = label;
        }

        public String getLabel()
        {
            return _label;
        }

        /**
         * Returns a label enumerating all the individual ACL perms
         * that the specified permission posseses.
         */
        public static String getLabel(int permissions)
        {
            StringBuffer sb = new StringBuffer();
            String concat = "";

            for (Pair<Integer, String> pair : _allPerms)
            {
                if ((pair.getKey() & permissions) != 0)
                {
                    sb.append(concat);
                    sb.append(pair.getValue());
                    concat = "|";
                }
            }
            return sb.toString();
        }

        public int getPermissions()
        {
            return _permissions;
        }

        public static boolean isPredefinedPermission(int permissions)
        {
            return findPermissionSet(permissions) != null;
        }

        private static int normalizePermissions(int permissions)
        {
            permissions |= (permissions & (ACL.PERM_READ | ACL.PERM_UPDATE | ACL.PERM_DELETE)) << 4;
            return permissions;
        }

        public static PermissionSet findPermissionSet(int permissions)
        {
            for (PermissionSet set : values())
            {
                // we try normalizing because a permissions value with just reader set is equivalent
                // to a permissions value with reader and read_own set.
                if (set.getPermissions() == permissions || normalizePermissions(set.getPermissions()) == permissions)
                    return set;
            }
            return null;
        }
    }


    private SecurityManager()
    {
    }


    private static boolean init = false;

    public static void init()
    {
        if (init)
            return;
        init = true;

        // HACK: I really want to make sure we don't have orphaned Groups.typeProject groups
        //
        // either because
        //  a) the container is non-existant or
        //  b) the container is not longer a project

        scrubTables();

        ContainerManager.addContainerListener(new SecurityContainerListener());
    }


    //
    // GroupListener
    //

    public interface GroupListener extends PropertyChangeListener
    {
        void principalAddedToGroup(Group group, UserPrincipal principal);

        void principalDeletedFromGroup(Group group, UserPrincipal principal);
    }

    private static final ArrayList<GroupListener> _listeners = new ArrayList<GroupListener>();

    public static void addGroupListener(GroupListener listener)
    {
        synchronized (_listeners)
        {
            _listeners.add(listener);
        }
    }

    protected static GroupListener[] getListeners()
    {
        synchronized (_listeners)
        {
            return _listeners.toArray(new GroupListener[_listeners.size()]);
        }
    }

    protected static void fireAddPrincipalToGroup(Group group, UserPrincipal user)
    {
        if (user == null)
            return;
        GroupListener[] list = getListeners();
        for (GroupListener GroupListener : list)
        {
            try
            {
                GroupListener.principalAddedToGroup(group, user);
            }
            catch (Throwable t)
            {
                _log.error("fireAddPrincipalToGroup", t);
            }
        }
    }

    protected static List<Throwable> fireDeletePrincipalFromGroup(int groupId, UserPrincipal user)
    {
        List<Throwable> errors = new ArrayList<Throwable>();
        if (user == null)
            return errors;

        Group group = getGroup(groupId);

        GroupListener[] list = getListeners();
        for (GroupListener GroupListener : list)
        {
            try
            {
                GroupListener.principalDeletedFromGroup(group, user);
            }
            catch (Throwable t)
            {
                _log.error("fireDeletePrincipalFromGroup", t);
                errors.add(t);
            }
        }
        return errors;
    }

    private static void scrubTables()
    {
        try
        {
            Container root = ContainerManager.getRoot();

            // missing container
            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoPrincipals() + "\n" +
                    "WHERE Container NOT IN (SELECT EntityId FROM " + core.getTableInfoContainers() + ")", null);

            // container is not a project (but should be)
            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoPrincipals() + "\n" +
                    "WHERE Type='g' AND Container NOT IN (SELECT EntityId FROM " + core.getTableInfoContainers() + "\n" +
                    "\tWHERE Parent=? OR Parent IS NULL)", new Object[] {root});

            // missing group
            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoMembers() + "\n" +
                    "WHERE GroupId NOT IN (SELECT UserId FROM " + core.getTableInfoPrincipals() + " WHERE Type IN ('m','g'))", null);

            // missing user
            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoMembers() + "\n" +
                    "WHERE UserId NOT IN (SELECT UserId FROM " + core.getTableInfoPrincipals() + " WHERE Type IN ('u'))", null);
        }
        catch (SQLException x)
        {
            _log.error(x);
        }
    }


    private static class SecurityContainerListener implements ContainerManager.ContainerListener
    {
        //void wantsToDelete(Container c, List<String> messages);
        public void containerCreated(Container c)
        {
        }

        public void containerDeleted(Container c, User user)
        {
            deleteGroups(c, null);
        }

        public void propertyChange(PropertyChangeEvent evt)
        {
            /* NOTE move is handled by direct call from ContainerManager into SecurityManager */
        }
    }



    // Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    public static User authenticateBasic(String basic)
    {
        try
        {
            byte[] decode = Base64.decodeBase64(basic.getBytes());
            String auth = new String(decode);
            int colon = auth.indexOf(':');
            if (-1 == colon)
                return null;
            String rawEmail = auth.substring(0, colon);
            String password = auth.substring(colon+1);
            new ValidEmail(rawEmail);  // validate email address
            User u = AuthenticationManager.authenticate(rawEmail, password);
            return u;
        }
        catch (ValidEmail.InvalidEmailException e)
        {
            throw new RuntimeException(e);
        }
    }


    // This user has been authenticated, but may not exist (if user was added to the database and is visiting for the first
    //  time or user authenticated using LDAP, SSO, etc.)
    public static User createUserIfNecessary(ValidEmail email)
    {
        User u = UserManager.getUser(email);

        // If user is authenticated but doesn't exist in our system then
        // add user to the database... must be an LDAP or SSO user's first visit
        if (null == u)
        {
            try
            {
                u = UserManager.createUser(email);
                UserManager.addToUserHistory(u, u.getEmail() + " authenticated successfully and was added to the system automatically.");
            }
            catch (SQLException e)
            {
                // do nothing; we'll fall through and return null.
            }
        }

        if (null != u)
            UserManager.updateLogin(u);

        return u;
    }


    public static final String AUTHENTICATION_METHOD = "SecurityManager.authenticationMethod";

    public static User getAuthenticatedUser(HttpServletRequest request)
    {
        User u = (User) request.getUserPrincipal();
        if (null == u)
        {
            User sessionUser = null;
            Integer userId = (Integer) request.getSession(true).getAttribute(User.class.getName() + "$userId");
            if (null != userId)
                sessionUser = UserManager.getUser(userId.intValue());
            if (null != sessionUser)
            {
                // We want groups membership to be calculated on every request (but just once)
                // the cloned User will calculate groups exactly once
                // NOTE: getUser() returns a cloned object
                // u = sessionUser.cloneUser();
                assert sessionUser._groups == null;
                sessionUser._groups = null;
                u = sessionUser;
            }
        }
        if (null == u)
        {
            // Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
            String authorization = request.getHeader("Authorization");
            if (null != authorization && authorization.startsWith("Basic"))
            {
                u = authenticateBasic(authorization.substring("Basic".length()).trim());
                if (null != u)
                {
                    request.setAttribute(AUTHENTICATION_METHOD, "Basic");
                    SecurityManager.setAuthenticatedUser(request, u);
                }
            }
        }
        return null == u || u.isGuest() ? null : u;
    }


    public static void setAuthenticatedUser(HttpServletRequest request, User u)
    {
        HttpSession s = request.getSession(true);
        s.setAttribute(User.class.getName() + "$userId", u.getUserId());
        s.setAttribute("LABKEY.username", u.getName());
        s.removeAttribute(TERMS_APPROVED_KEY);   // Clear approved terms-of-use on every login (or impersonation)
    }


    public static void logoutUser(HttpServletRequest request)
    {
        User user = (User)request.getUserPrincipal();
        AuthenticationManager.logout(user, request);   // Let AuthenticationProvider clean up auth-specific cookies, etc.

        HttpSession s = request.getSession();
        if (null != s)
            s.invalidate();
    }


    private static final String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    public static final int tempPasswordLength = 32;

    public static String createTempPassword()
    {
        StringBuffer tempPassword = new StringBuffer(tempPasswordLength);

        for (int i = 0; i < tempPasswordLength; i++)
            tempPassword.append(passwordChars.charAt((int) Math.floor((Math.random() * passwordChars.length()))));

        return tempPassword.toString();
    }


    public static ActionURL createVerificationUrl(Container c, String email, String verification, Pair<String, String>[] extraParameters)
    {
        ActionURL url = new ActionURL("login", "setPassword", c);
        url.addParameter("verification", verification);
        url.addParameter("email", email);

        if (null != extraParameters)
            url.addParameters(extraParameters);

        return url;
    }


    // Test if non-LDAP email has been verified
    public static boolean isVerified(ValidEmail email) throws UserManagementException
    {
        return (null == getVerification(email));
    }


    public static boolean verify(ValidEmail email, String verification) throws UserManagementException
    {
        String dbVerification = getVerification(email);
        return (dbVerification != null && dbVerification.equals(verification));
    }


    public static void setVerification(ValidEmail email, String verification) throws UserManagementException
    {
        try
        {
            int rows = Table.execute(core.getSchema(), "UPDATE " + core.getTableInfoLogins() + " SET Verification=? WHERE email=?", new Object[]{verification, email.getEmailAddress()});
            if (1 != rows)
                throw new UserManagementException(email, "Unexpected number of rows returned when setting verification: " + rows);
        }
        catch (SQLException e)
        {
            _log.error("setVerification: ", e);
            throw new UserManagementException(email, e);
        }
    }


    public static String getVerification(ValidEmail email) throws UserManagementException
    {
        try
        {
            return Table.executeSingleton(core.getSchema(), "SELECT Verification FROM " + core.getTableInfoLogins() + " WHERE email=?", new Object[]{email.getEmailAddress()}, String.class);
        }
        catch (SQLException e)
        {
            _log.error("verify: ", e);
            throw new UserManagementException(email, e);
        }
    }


    public static class NewUserBean
    {
        private String email;
        private String verification;
        private boolean ldap;
        private User user;

        public NewUserBean(String email)
        {
            setEmail(email);
        }

        public String getEmail()
        {
            return email;
        }

        public void setEmail(String email)
        {
            this.email = email;
        }

        public boolean isLdap()
        {
            return ldap;
        }

        public void setLdap(boolean ldap)
        {
            this.ldap = ldap;
        }

        public String getVerification()
        {
            return verification;
        }

        public void setVerification(String verification)
        {
            this.verification = verification;
        }

        public User getUser()
        {
            return user;
        }

        public void setUser(User user)
        {
            this.user = user;
        }
    }


    public static class UserManagementException extends Exception
    {
        private String _email;

        public UserManagementException(ValidEmail email, String message)
        {
            super(message);
            _email = email.getEmailAddress();
        }

        public UserManagementException(String email, String message)
        {
            super(message);
            _email = email;
        }

        public UserManagementException(ValidEmail email, String message, Exception cause)
        {
            super(message, cause);
            _email = email.getEmailAddress();
        }

        public UserManagementException(ValidEmail email, Exception cause)
        {
            super(cause);
            _email = email.getEmailAddress();
        }

        public UserManagementException(String email, Exception cause)
        {
            super(cause);
            _email = email;
        }

        public String getEmail()
        {
            return _email;
        }
    }

    public static class UserAlreadyExistsException extends UserManagementException
    {
        public UserAlreadyExistsException(String email)
        {
            super(email, "User already exists");
        }
    }

    public static NewUserBean addUser(ValidEmail email) throws UserManagementException
    {
        NewUserBean newUserBean = new NewUserBean(email.getEmailAddress());

        if (UserManager.userExists(email))
            throw new UserAlreadyExistsException(email.getEmailAddress());

        if (!SecurityManager.isLdapEmail(email))
        {
            // Create a placeholder password that's hard to guess and a separate email verification
            // key that gets emailed.
            newUserBean.setLdap(false);

            String tempPassword = SecurityManager.createTempPassword();
            String verification = SecurityManager.createTempPassword();

            SecurityManager.createLogin(email, tempPassword, verification);

            newUserBean.setVerification(verification);
        }
        else
        {
            newUserBean.setLdap(true);
        }

        User newUser;
        try
        {
            newUser = UserManager.createUser(email);
        }
        catch (SQLException e)
        {
            throw new UserManagementException(email, "Unable to create user.", e);
        }

        if (null == newUser)
            throw new UserManagementException(email, "Couldn't create user.");

        newUserBean.setUser(newUser);
        return newUserBean;
    }


    public static void sendEmail(User user, SecurityMessage message, String to, String verificationUrl) throws MessagingException
    {
        MimeMessage m = createMessage(user, message, to, verificationUrl);
        MailHelper.send(m);
    }

    public static void renderEmail(User user, SecurityMessage message, String to, String verificationUrl, Writer out) throws MessagingException
    {
        MimeMessage m = createMessage(user, message, to, verificationUrl);
        MailHelper.renderHtml(m, message.getType(), out);
    }

    private static MimeMessage createMessage(User user, SecurityMessage message, String to, String verificationUrl) throws MessagingException
    {
        try
        {
            message.setVerificationURL(verificationUrl);
            message.setFrom(user.getEmail());
            if (message.getTo() == null)
                message.setTo(to);

            MimeMessage m = message.createMailMessage();

            m.addFrom(new Address[]{new InternetAddress(user.getEmail(), user.getFullName())});
            m.addRecipients(Message.RecipientType.TO, to);

            return m;
        }
        catch (UnsupportedEncodingException e)
        {
            throw new MessagingException("Failed to create InternetAddress.", e);
        }
        catch (Exception e)
        {
            throw new MessagingException("Failed to set template context.", e);
        }
    }

    // Create record for non-LDAP login, saving email address and hashed password
    public static void createLogin(ValidEmail email, String password, String verification) throws UserManagementException
    {
        try
        {
            int rowCount = Table.execute(core.getSchema(), "INSERT INTO " + core.getTableInfoLogins() + " (Email, Crypt, Verification) VALUES (?, ?, ?)", new Object[]{email.getEmailAddress(), Crypt.digest(password), verification});
            if (1 != rowCount)
                throw new UserManagementException(email, "Login creation statement affected " + rowCount + " rows.");
        }
        catch (SQLException e)
        {
            _log.error("createLogin", e);
            throw new UserManagementException(email, e);
        }
    }


    public static void setPassword(ValidEmail email, String password) throws UserManagementException
    {
        try
        {
            int rows = Table.execute(core.getSchema(), "UPDATE " + core.getTableInfoLogins() + " SET Crypt=? WHERE Email=?", new Object[]{Crypt.digest(password), email.getEmailAddress()});
            if (1 != rows)
                throw new UserManagementException(email, "Password update statement affected " + rows + " rows.");
        }
        catch (SQLException e)
        {
            _log.error("setPassword", e);
            throw new UserManagementException(email, e);
        }
    }


    // Look up email in Logins table and return the corresponding password hash
    public static String getPasswordHash(ValidEmail email)
    {
        String hash = null;

        try
        {
            hash = Table.executeSingleton(core.getSchema(), "SELECT Crypt FROM " + core.getTableInfoLogins() + " WHERE Email=?", new Object[]{email.getEmailAddress()}, String.class);
        }
        catch (SQLException e)
        {
            _log.error("getPasswordHash: Retrieving Crypt failed.", e);
        }

        return hash;
    }


    public static boolean loginExists(ValidEmail email)
    {
        return (null != getPasswordHash(email));
    }


    public static Group createGroup(Container c, String name)
    {
        return createGroup(c, name, Group.typeProject);
    }


    public static Group createGroup(Container c, String name, String type)
    {
        String defaultOwnerId = c.isRoot() ? null : c.getId();
        return createGroup(c, name, type, defaultOwnerId);
    }


    public static Group createGroup(Container c, String name, String type, String ownerId)
    {
        String containerId = c.isRoot() ? null : c.getId();
        Group group = new Group();
        group.setName(StringUtils.trimToNull(name));
        group.setOwnerId(ownerId);
        group.setContainer(containerId);
        group.setType(type);

        if (null == group.getName())
            throw new IllegalArgumentException("Group can not have blank name");

        String valid = UserManager.validGroupName(group.getName(), group.getType());
        if (null != valid)
            throw new IllegalArgumentException(valid);

        if (groupExists(c, group.getName(), group.getOwnerId()))
            throw new IllegalArgumentException("Group already exists");

        try
        {
            Table.insert(null, core.getTableInfoPrincipals(), group);
        }
        catch (SQLException e)
        {
            throw new RuntimeSQLException(e);
        }

        return group;
    }


    // Case-insensitive existence check -- disallows groups that differ only by case
    private static boolean groupExists(Container c, String groupName, String ownerId)
    {
        return null != getGroupId(c, groupName, ownerId, false, true);
    }


    public static void deleteGroup(String groupPath)
    {
        Integer groupId = getGroupId(groupPath);
        if (groupId == null)
            return;
        deleteGroup(groupId);
    }


    public static void deleteGroup(Group group)
    {
        deleteGroup(group.getUserId());
    }


    static void deleteGroup(int groupId)
    {
        if (groupId == Group.groupAdministrators ||
                groupId == Group.groupGuests ||
                groupId == Group.groupUsers)
            throw new IllegalArgumentException("The global groups cannot be deleted.");

        try
        {
            removeGroupFromCache(groupId);

            Filter groupFilter = new SimpleFilter("GroupId", groupId);
            Table.delete(core.getTableInfoMembers(), groupFilter);

            Filter principalsFilter = new SimpleFilter("UserId", groupId);
            Table.delete(core.getTableInfoPrincipals(), principalsFilter);
        }
        catch (SQLException x)
        {
            throw new RuntimeSQLException(x);
        }
    }


    public static void deleteGroups(Container c, String type)
    {
        if (!(null == type || type.equals(Group.typeProject) || type.equals(Group.typeModule) ))
            throw new IllegalArgumentException("Illegal group type: " + type);

        if (null == type)
            type = "%";

        try
        {
            removeAllGroupsFromCache();

            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoMembers() + "\n"+
                    "WHERE GroupId in (SELECT UserId FROM " + core.getTableInfoPrincipals() +
                    "\tWHERE Container=? and Type LIKE ?)", new Object[] {c, type});
            Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoPrincipals() +
                    "\tWHERE Container=? AND Type LIKE ?", new Object[] {c, type});
        }
        catch (SQLException x)
        {
            _log.error("Delete group", x);
            throw new RuntimeSQLException(x);
        }
    }


    public static void deleteMembers(Group group, List<ValidEmail> emailsToDelete)
    {
        int groupId = group.getUserId();

        if (emailsToDelete != null && !emailsToDelete.isEmpty())
        {
            Iterator<ValidEmail> it = emailsToDelete.iterator();
            StringBuilder deleteString = new StringBuilder();
            while (it.hasNext())
            {
                ValidEmail email = it.next();
                deleteString.append("'").append(email.getEmailAddress()).append("'");
                if (it.hasNext())
                    deleteString.append(", ");
            }

            try
            {
                Table.execute(
                        core.getSchema(),
                        "DELETE FROM " + core.getTableInfoMembers() + "\n" +
                                "WHERE GroupId = ? AND UserId IN\n" +
                                "(SELECT M.UserId\n" +
                                "FROM " + core.getTableInfoMembers() + " M JOIN " + core.getTableInfoPrincipals() + " P ON M.UserId = P.UserId\n" +
                                "WHERE GroupId = ? AND Name IN (" + deleteString.toString() + "))",
                        new Object[]{groupId, groupId});
            }
            catch (SQLException e)
            {
                throw new RuntimeSQLException(e);
            }

            for (ValidEmail email : emailsToDelete)
                fireDeletePrincipalFromGroup(groupId, UserManager.getUser(email));
        }
    }


    public static void deleteMember(Group group, UserPrincipal principal)
    {
        int groupId = group.getUserId();

        try
        {
            Table.execute(
                    core.getSchema(),
                    "DELETE FROM " + core.getTableInfoMembers() + "\n" +
                            "WHERE GroupId = ? AND UserId = ?",
                    new Object[]{groupId, principal.getUserId()});
        }
        catch (SQLException e)
        {
            throw new RuntimeSQLException(e);
        }

        fireDeletePrincipalFromGroup(groupId, principal);
    }


    public static void addMembers(Group group, List<ValidEmail> emailsToAdd) throws SQLException
    {
        int groupId = group.getUserId();

        if (emailsToAdd != null && !emailsToAdd.isEmpty())
        {
            Iterator<ValidEmail> it = emailsToAdd.iterator();
            StringBuilder addString = new StringBuilder();
            while (it.hasNext())
            {
                ValidEmail email = it.next();
                addString.append("'").append(email.getEmailAddress()).append("'");

                if (it.hasNext())
                    addString.append(", ");
            }

            Table.execute(
                    core.getSchema(),
                    "INSERT INTO " + core.getTableInfoMembers() +
                            "\nSELECT UserId, ?\n" +
                            "FROM " + core.getTableInfoPrincipals() +
                            "\nWHERE Name IN (" + addString.toString() + ") AND Name NOT IN\n" +
                            "  (SELECT Name FROM " + core.getTableInfoMembers() + " _Members JOIN " + core.getTableInfoPrincipals() + " _Principals ON _Members.UserId = _Principals.UserId\n" +
                            "   WHERE GroupId = ?)",
                    new Object[]{groupId, groupId});
        }

        if (null != emailsToAdd)
            for (ValidEmail email : emailsToAdd)
                fireAddPrincipalToGroup(group, UserManager.getUser(email));
    }


    /** @deprecated */
    public static void addMember(Integer groupId, User user)
    {
        Group group = getGroup(groupId);
        addMember(group, user);
    }

    // Add a single user to a single group
    public static void addMember(Group group, UserPrincipal user)
    {
        try
        {
            Table.execute(
                    core.getSchema(),
                    "INSERT INTO " + core.getTableInfoMembers() + " (UserId, GroupId) VALUES (?, ?)",
                    new Object[]{user.getUserId(), group.getUserId()});
            fireAddPrincipalToGroup(group, user);
        }
        catch (SQLException e)
        {
            _log.error("addMember", e);
        }
    }


    public static Group[] getGroups(Container project, boolean includeGlobalGroups)
    {
        try
        {
            if (null == project)
            {
                return Table.executeQuery(
                        core.getSchema(),
                        "SELECT Name, UserId, Container FROM " + core.getTableInfoPrincipals() + " WHERE Type='g' AND Container IS NULL ORDER BY LOWER(Name)",  // Force case-insensitve order for consistency
                        null,
                        Group.class);
            }
            else
            {
                String projectClause = (includeGlobalGroups ? "(Container = ? OR Container IS NULL)" : "Container = ?");

                // Postgres and SQLServer disagree on how to sort null, so we need to handle
                // null Container values as the first ORDER BY criteria
                return Table.executeQuery(
                        core.getSchema(),
                        "SELECT Name, UserId, Container FROM " + core.getTableInfoPrincipals() + "\n" +
                                "WHERE Type='g' AND " + projectClause + "\n" +
                                "ORDER BY CASE WHEN ( Container IS NULL ) THEN 1 ELSE 2 END, Container, LOWER(Name)",  // Force case-insensitve order for consistency
                        new Object[]{project.getId()},
                        Group.class);
            }
        }
        catch (SQLException e)
        {
            _log.error("unexpected exception", e);
            throw new RuntimeSQLException(e);
        }
    }


    public static Group getGroup(int groupId)
    {
        Group group = (Group)Cache.getShared().get(GROUP_CACHE_PREFIX + groupId);

        if (null == group)
        {
            try
            {
                Group[] groups = Table.executeQuery(
                        core.getSchema(),
                        "SELECT Name, UserId, Container FROM " + core.getTableInfoPrincipals() + " WHERE type <> 'u' AND userId=?",
                        new Object[] {groupId},
                        Group.class);
                assert groups.length <= 1;
                group = groups.length == 0 ? null : groups[0];
                Cache.getShared().put(GROUP_CACHE_PREFIX + groupId, group);
            }
            catch (SQLException e)
            {
                _log.error("unexpected exception", e);
                throw new RuntimeSQLException(e);
            }
        }

        return group;
    }


    private static void removeGroupFromCache(int groupId)
    {
        Cache.getShared().remove(GROUP_CACHE_PREFIX + groupId);
    }


    private static void removeAllGroupsFromCache()
    {
        Cache.getShared().removeUsingPrefix(GROUP_CACHE_PREFIX);
    }


    public static List<User> getProjectMembers(Container c)
    {
        return getProjectMembers(c, false);
    }


    // Returns common separated list of group names this user belongs to in this container
    public static String getGroupList(Container c, User u)
    {
        Container proj = c.getProject();
        int[] groupIds = u.getGroups();

        StringBuilder groupList = new StringBuilder();
        String sep = "";

        for (int groupId : groupIds)
        {
            // Ignore Guest, Users, Admins, and user's own id
            if (groupId > 0 && groupId != u.getUserId())
            {
                Group g = SecurityManager.getGroup(groupId);

                // Only groups in this project
                if (g.getContainer().equals(proj.getId()))
                {
                    groupList.append(sep);
                    groupList.append(g.getName());
                    sep = ", ";
                }
            }
        }

        return groupList.toString();
    }


    public static List<User> getProjectMembers(Container c, boolean includeGlobal)
    {
        if (c != null && !c.isProject())
            c = c.getProject();

        Group[] groups = getGroups(c, includeGlobal);
        Set<String> emails = new HashSet<String>();

       //get members for each group
        ArrayList<User> projectMembers = new ArrayList<User>();
        String[] members;

        try
        {
            for(Group g : groups)
            {
                if (g.isGuests() || g.isUsers())
                    continue;

                if (g.isProjectGroup())
                    members = getGroupMemberNames(getGroupId(c, g.getName()));
                else
                    members = getGroupMemberNames(getGroupId(null, g.getName()));

                //add this group's members to hashset
                if (members != null)
                {
                    //get list of users from email
                    for (String member : members)
                    {
                        if (emails.add(member))
                            projectMembers.add(UserManager.getUser(new ValidEmail(member)));
                    }
                }
            }
            return projectMembers;
        }
        catch (SQLException e)
        {
            _log.error("unexpected error", e);
            throw new RuntimeSQLException(e);
        }
        catch (ValidEmail.InvalidEmailException e)
        {
            _log.error("unexpected error", e);
            throw new RuntimeException(e);
        }
    }


    public static List<User> getUsersWithPermissions(Container c, int perm) throws SQLException
    {
        // No cache right now, but performance seems fine.  After the user list and acl is cached, no other queries occur.
        User[] allUsers = UserManager.getAllUsers();
        List<User> users = new ArrayList<User>(allUsers.length);
        ACL acl = c.getAcl();

        for (User user : allUsers)
            if (acl.hasPermission(user, perm))
                users.add(user);

        return users;
    }


    public static List<Pair<Integer, String>> getGroupMemberNamesAndIds(String path)
    {
        try
        {
            Integer groupId = SecurityManager.getGroupId(path);
            if (groupId == null)
                return Collections.emptyList();
            else
                return getGroupMemberNamesAndIds(groupId);
        }
        catch (SQLException e)
        {
            _log.error(e);
            throw new RuntimeSQLException(e);
        }
    }

    public static String[] getGroupMemberNames(String path)
    {
        try
        {
            Integer groupId = SecurityManager.getGroupId(path);
            if (groupId == null)
                return new String[0];
            else
                return getGroupMemberNames(groupId);
        }
        catch (SQLException e)
        {
            _log.error(e);
            throw new RuntimeSQLException(e);
        }
    }

    public static List<Pair<Integer,String>> getGroupMemberNamesAndIds(Integer groupId) throws SQLException
    {
        ResultSet rs = null;
        try
        {
             rs = Table.executeQuery(
                    core.getSchema(),
                    "SELECT Users.UserId, Users.Name\n" +
                            "FROM " + core.getTableInfoMembers() + " JOIN " + core.getTableInfoPrincipals() + " Users ON " + core.getTableInfoMembers() + ".UserId = Users.UserId\n" +
                            "WHERE GroupId = ?\n" +
                            "ORDER BY Users.Name",
                    new Object[]{groupId});
            List<Pair<Integer,String>> members = new ArrayList<Pair<Integer, String>>();
            while (rs.next())
                members.add(new Pair<Integer,String>(rs.getInt(1), rs.getString(2)));
            return members;
        }
        catch (SQLException e)
        {
            _log.error(e);
            throw e;
        }
        finally
        {
            if (rs != null)
            {
                try { rs.close(); }
                catch (SQLException e)
                {
                    //ignore
                }
            }
        }
    }

    public static String[] getGroupMemberNames(Integer groupId) throws SQLException
    {
        List<Pair<Integer, String>> members = getGroupMemberNamesAndIds(groupId);
        String[] names = new String[members.size()];
        int i = 0;
        for (Pair<Integer, String> member : members)
            names[i++] = member.getValue();
        return names;
    }


    public static Integer[] getGroupMemberIds(Container c, String groupName)
    {
        try
        {
            Integer groupId = SecurityManager.getGroupId(c, groupName);
            return Table.executeArray(core.getSchema(), "SELECT UserId FROM " + core.getTableInfoMembers() + " WHERE GroupId = ?", new Object[]{groupId}, Integer.class);
        }
        catch (SQLException e)
        {
            _log.error(e);
        }

        return new Integer[ 0 ];
    }


    // Takes string such as "/test/subfolder/Users" and returns groupId
    public static Integer getGroupId(String extraPath)
    {
        if (extraPath.startsWith("/"))
            extraPath = extraPath.substring(1);

        int slash = extraPath.lastIndexOf('/');
        String group = extraPath.substring(slash + 1);
        Container c = null;
        if (slash != -1)
        {
            String path = extraPath.substring(0, slash);
            c = ContainerManager.getForPath(path);
            if (null == c)
                HttpView.throwNotFound();
        }

        return getGroupId(c, group);
    }


    // Takes Container (or null for root) and group name; returns groupId
    public static Integer getGroupId(Container c, String group)
    {
        return getGroupId(c, group, null, true);
    }


    // Takes Container (or null for root) and group name; returns groupId
    public static Integer getGroupId(Container c, String group, boolean throwOnFailure)
    {
        return getGroupId(c, group, null, throwOnFailure);
    }


    // Takes Container (or null for root) and group name; returns groupId
    public static Integer getGroupId(Container c, String group, String ownerId)
    {
        return getGroupId(c, group, ownerId, true);
    }


    public static Integer getGroupId(Container c, String groupName, String ownerId, boolean throwOnFailure)
    {
        return getGroupId(c, groupName, ownerId, throwOnFailure, false);
    }


    // This is temporary... in CPAS 1.5 on PostgreSQL it was possible to create two groups in the same container that differed only
    // by case (this was not possible on SQL Server).  In CPAS 1.6 we disallow this on PostgreSQL... but we still need to be able to
    // retrieve group IDs in a case-sensitive manner.
    // TODO: For CPAS 1.7: this should always be case-insensitive (we will clean up the database by renaming duplicate groups)
    private static Integer getGroupId(Container c, String groupName, String ownerId, boolean throwOnFailure, boolean caseInsensitive)
    {
        List<String> params = new ArrayList<String>();
        params.add(caseInsensitive ? groupName.toLowerCase() : groupName);
        String sql = "SELECT UserId FROM " + core.getTableInfoPrincipals() + " WHERE " + (caseInsensitive ? "LOWER(Name)" : "Name") + " = ? AND Container ";
        if (c == null)
            sql += "IS NULL";
        else
        {
            sql += "= ?";
            params.add(c.getId());
            if (ownerId == null)
                ownerId = c.isRoot() ? null : c.getId();
        }

        if (ownerId == null)
            sql += " AND OwnerId IS NULL";
        else
        {
            sql += " AND OwnerId = ?";
            params.add(ownerId);
        }

        Integer groupId;
        try
        {
            groupId = Table.executeSingleton(core.getSchema(), sql,
                    params.toArray(new Object[params.size()]), Integer.class);
        }
        catch (SQLException x)
        {
            throw new RuntimeSQLException(x);
        }
        if (groupId == null && throwOnFailure)
            HttpView.throwNotFound();

        return groupId;
    }


    public static boolean isTermsOfUseRequired(Project project)
    {
        //TODO: Should do this more efficiently, but no efficient public wiki api for this yet
        return null != getTermsOfUseHtml(project);
    }


    public static String getTermsOfUseHtml(Project project)
    {
        if (null == project)
            return null;

        if (!ModuleLoader.getInstance().isStartupComplete())
            return null;
        
        WikiService.Service service;
        try
        {
            service = WikiService.get();
        }
        catch (IllegalStateException x)
        {
            //No wiki service. Must be in weird state. Don't do terms here...
            return null;
        }

        return service.getHtml(project.getContainer(), TERMS_OF_USE_WIKI_NAME, false);
    }


    public static boolean isTermsOfUseRequired(ViewContext ctx)
    {
        Container c = ctx.getContainer();
        if (null == c)
            return false;

        Container proj = c.getProject();
        if (null == proj)
            return false;

        Project project = new Project(proj);

        if ("Basic".equals(ctx.getRequest().getAttribute(AUTHENTICATION_METHOD)) || getTermsOfUseApproved(ctx, project))
            return false;

        ActionURL url = ctx.getActionURL();
        if (url != null && "query".equalsIgnoreCase(url.getPageFlow()) && "excelWebQuery".equalsIgnoreCase(url.getAction()))
            return false;

        boolean required = isTermsOfUseRequired(project);

        //stash result so that this is faster next time.
        if (!required)
            setTermsOfUseApproved(ctx, project, true);

        return required;
    }


    private static final String TERMS_APPROVED_KEY = "TERMS_APPROVED_KEY";
    private static final Object TERMS_APPROVED_LOCK = new Object();

    public static boolean getTermsOfUseApproved(ViewContext ctx, Project project)
    {
        if (null == project)
            return true;

        synchronized (TERMS_APPROVED_LOCK)
        {
            HttpSession session = ctx.getRequest().getSession(true);
            Set<Project> termsApproved = (Set<Project>) session.getAttribute(TERMS_APPROVED_KEY);
            return null != termsApproved && termsApproved.contains(project);
        }
    }


    public static void setTermsOfUseApproved(ViewContext ctx, Project project, boolean approved)
    {
        if (null == project)
            return;

        synchronized (TERMS_APPROVED_LOCK)
        {
            HttpSession session = ctx.getRequest().getSession(true);
            Set<Project> termsApproved = (Set<Project>) session.getAttribute(TERMS_APPROVED_KEY);
            if (null == termsApproved)
            {
                termsApproved = new HashSet<Project>();
                session.setAttribute(TERMS_APPROVED_KEY, termsApproved);
            }
            if (approved)
                termsApproved.add(project);
            else
                termsApproved.remove(project);
        }
    }
    

    // CONSIDER: Support multiple LDAP domains?
    public static boolean isLdapEmail(ValidEmail email)
    {
        String ldapDomain = AuthenticationManager.getLdapDomain();
        return ldapDomain != null && email.getEmailAddress().endsWith("@" + ldapDomain.toLowerCase());
    }


    // Password rule: regular expression and English language version for error messages
    // TODO: Add these to AppProps
    public static final String passwordRule = "Passwords must be six characters or more and can't match your email address.";
    private static Pattern passwordPattern = Pattern.compile("^\\S{6,}$");  // At least six, non-whitespace characters

    // Make sure password is strong enough.
    public static boolean isValidPassword(String password, ValidEmail email)
    {
        if (null != password)
            return passwordPattern.matcher(password).matches() && !email.getEmailAddress().equalsIgnoreCase(password);  // Passes rule and doesn't match email address
        else
            return false;
    }


    //
    // Permissions, ACL cache and Permission testing
    //

    private static String _aclPrefix = "ACL/";


    public static ACL getACL(Container c)
    {
        return getACL(c.getId(), c.getId());
    }


    public static ACL getACL(Container c, String objectID)
    {
        return getACL(c.getId(), objectID);
    }


    private static ACL getACL(String containerId, String objectId)
    {
        String cacheName = cacheName(containerId, objectId);
        ACL acl = (ACL) DbCache.get(core.getTableInfoACLs(), cacheName);
        if (null != acl)
            return acl;

        try
        {
            byte[] bytes = Table.executeSingleton(core.getSchema(), "SELECT ACL FROM " + core.getTableInfoACLs() + " WHERE Container = ? AND ObjectId = ?",
                    new Object[]{containerId, objectId}, byte[].class);
            // NB: we want every object to have a unique ACL object in the cache
            // even if the ACL is empty.  This way users can keep weak references to the ACL for performance.
            // If the ACL goes away, they refresh.  This doesn't work if there is a special _empty_ acl
            acl = new ACL(bytes);
            DbCache.put(core.getTableInfoACLs(), cacheName, acl);
            return acl;
        }
        catch (SQLException e)
        {
            throw new RuntimeSQLException(e);
        }
    }


    public static void updateACL(Container c, ACL acl)
    {
        updateACL(c, c.getId(), acl);
    }


    public static ActionURL getPermissionsUrl(Container c)
    {
        return new ActionURL("Security", "container", c);
    }


    // Modules register a factory to add module-specific ui to the permissions page
    public static void addViewFactory(ViewFactory vf)
    {
        _viewFactories.add(vf);
    }


    public static List<ViewFactory> getViewFactories()
    {
        return _viewFactories;
    }


    public interface ViewFactory
    {
        public HttpView createView(ViewContext context);
    }


    private static String cacheName(String c, String objectId)
    {
        return _aclPrefix + c + "/" + objectId;
    }


    public static void updateACL(Container c, String objectId, ACL acl)
    {
        byte[] bytes = acl.toByteArray();
        int rowCount;

        try
        {
            rowCount = Table.execute(core.getSchema(), "UPDATE " + core.getTableInfoACLs() + " SET ACL=? WHERE Container = ? AND ObjectId = ?",
                    new Object[]{bytes, c.getId(), objectId});
        }
        catch (SQLException x)
        {
            // hack for upgrade 1.20->1.21
            if (!c.getId().equals(objectId))
                throw new RuntimeSQLException(x);
            try
            {
            rowCount = Table.execute(core.getSchema(), "UPDATE " + core.getTableInfoACLs() + " SET ACL=? WHERE ObjectId = ?",
                    new Object[]{bytes, objectId});
            }
            catch (SQLException y)
            {
                throw new RuntimeSQLException(x);   // original exception
            }
        }

        if (0 == rowCount)
        {
            try
            {
            Table.execute(core.getSchema(), "INSERT INTO " + core.getTableInfoACLs() + " (ACL, Container, ObjectId) VALUES (?,?,?)",
                    new Object[]{bytes, c.getId(), objectId});
            }
            catch (SQLException x)
            {
                // hack for upgrade 1.20->1.21
                if (!c.getId().equals(objectId))
                    throw new RuntimeSQLException(x);
                try
                {
                    Table.execute(core.getSchema(), "INSERT INTO " + core.getTableInfoACLs() + " (ACL, ObjectId) VALUES (?,?)",
                            new Object[]{bytes, objectId});
                }
                catch (SQLException y)
                {
                    throw new RuntimeSQLException(x);   // original exception
                }
            }
        }
        DbCache.remove(core.getTableInfoACLs(), cacheName(c.getId(), objectId));
        notifyACLChange(objectId);
    }



    public static void removeAll(Container c)
    {
        try
        {
        Table.execute(
                core.getSchema(),
                "DELETE FROM " + core.getTableInfoACLs() + " WHERE Container = ?",
                new Object[]{c.getId()});
        DbCache.clear(core.getTableInfoACLs());
        }
        catch (SQLException x)
        {
            throw new RuntimeSQLException(x);
        }
    }


    public static void removeACL(Container c, String objectID)
    {
        try
        {
        Table.execute(
                core.getSchema(),
                "DELETE FROM " + core.getTableInfoACLs() + " WHERE Container = ? AND ObjectId = ?",
                new Object[]{c.getId(), objectID});
        DbCache.remove(core.getTableInfoACLs(), cacheName(c.getId(), objectID));
        }
        catch (SQLException x)
        {
            throw new RuntimeSQLException(x);
        }
    }


    public static class TestCase extends junit.framework.TestCase
    {
        public TestCase()
        {
            super();
        }


        public TestCase(String name)
        {
            super(name);
        }


        public void testCreateUser() throws Exception
        {
            ValidEmail email;
            String rawEmail;

            // Just in case, loop until we find one that doesn't exist already
            while (true)
            {
                rawEmail = "test_" + Math.round(Math.random() * 10000) + "@localhost.xyz";
                email = new ValidEmail(rawEmail);
                if (!SecurityManager.loginExists(email)) break;
            }

            String password = createTempPassword();
            String verification = createTempPassword();
            int id;

            // Test create login, create user, verify, login, and delete
            try
            {
                SecurityManager.createLogin(email, password, verification);

                id = UserManager.createUser(email).getUserId();
                assertTrue("createUser", id != 0);

                boolean success = SecurityManager.verify(email, verification);
                assertTrue("verify", success);

                SecurityManager.setVerification(email, null);

                password = createTempPassword();
                SecurityManager.setPassword(email, password);

                User user = AuthenticationManager.authenticate(rawEmail, password);
                assertNotNull("login", user);
                assertEquals("login", user.getUserId(), id);
            }
            finally
            {
                UserManager.deleteUser(email);
            }
        }


        public void testACLS() throws NamingException
        {
            ACL acl = new ACL();

            // User,Guest
            User user = TestContext.get().getUser();
            assertFalse("no permission check", acl.hasPermission(user, ACL.PERM_READ));

            acl.setPermission(user.getUserId(), ACL.PERM_READ);
            assertTrue("read permission", acl.hasPermission(user, ACL.PERM_READ));
            assertFalse("no write permission", acl.hasPermission(user, ACL.PERM_UPDATE));

            acl = new ACL();
            acl.setPermission(Group.groupGuests, ACL.PERM_READ);
            assertTrue("read permission", acl.hasPermission(user, ACL.PERM_READ));
            assertFalse("no write permission", acl.hasPermission(user, ACL.PERM_UPDATE));

            acl.setPermission(Group.groupUsers, ACL.PERM_UPDATE);
            assertTrue("write permission", acl.hasPermission(user, ACL.PERM_UPDATE));
            assertEquals(acl.getPermissions(user), ACL.PERM_READ | ACL.PERM_READOWN | ACL.PERM_UPDATE | ACL.PERM_UPDATEOWN );

            // Guest
            assertTrue("read permission", acl.hasPermission(User.guest, ACL.PERM_READ));
            assertFalse("no write permission", acl.hasPermission(User.guest, ACL.PERM_UPDATE));
            assertEquals(acl.getPermissions(User.guest), ACL.PERM_READ | ACL.PERM_READOWN);
        }


        public void testEmailValidation()
        {
            testEmail("this@that.com", true);
            testEmail("foo@fhcrc.org", true);
            testEmail("dots.dots@dots.co.uk", true);
            testEmail("funny_chars#that%are^allowed&in*email!addresses@that.com", true);

            String displayName = "Personal Name";
            ValidEmail email = testEmail(displayName + " <personal@name.com>", true);
            assertTrue("Display name: expected '" + displayName + "' but was '" + email.getPersonal() + "'", displayName.equals(email.getPersonal()));

            String defaultDomain = ValidEmail.getDefaultDomain();
            // If default domain is defined this should succeed; if it's not defined, this should fail.
            testEmail("foo", defaultDomain != null && defaultDomain.length() > 0);

            testEmail("~()@bar.com", false);
            testEmail("this@that.com@con", false);
            testEmail(null, false);
            testEmail("", false);
            testEmail("<@bar.com", false);
            testEmail(displayName + " <personal>", false);  // Can't combine personal name with default domain
        }


        private ValidEmail testEmail(String rawEmail, boolean valid)
        {
            ValidEmail email = null;

            try
            {
                email = new ValidEmail(rawEmail);
                assertTrue(rawEmail, valid);
            }
            catch(ValidEmail.InvalidEmailException e)
            {
                assertFalse(rawEmail, valid);
            }

            return email;
        }


        public static Test suite()
        {
            return new TestSuite(TestCase.class);
        }
    }


    protected static void notifyACLChange(String objectID)
    {
        // UNDONE: generalize cross manager/module notifications
        ContainerManager.notifyContainerChange(objectID);
    }

    public static List<ValidEmail> normalizeEmails(String[] rawEmails, List<String> invalidEmails)
    {
        if (rawEmails == null || rawEmails.length == 0)
            return Collections.emptyList();
        return normalizeEmails(Arrays.asList(rawEmails), invalidEmails);
    }

    public static List<ValidEmail> normalizeEmails(List<String> rawEmails, List<String> invalidEmails)
    {
        if (rawEmails == null || rawEmails.size() == 0)
            return Collections.emptyList();

        List<ValidEmail> emails = new ArrayList<ValidEmail>(rawEmails.size());

        for (String rawEmail : rawEmails)
        {
            try
            {
                emails.add(new ValidEmail(rawEmail));
            }
            catch(ValidEmail.InvalidEmailException e)
            {
                invalidEmails.add(rawEmail);
            }
        }

        return emails;
    }

    public static SecurityMessage getRegistrationMessage(String mailPrefix, boolean isAdminCopy) throws Exception
    {
        SecurityMessage sm = new SecurityMessage();

        EmailTemplate et = EmailTemplateService.get().getEmailTemplate(
                isAdminCopy ? RegistrationAdminEmailTemplate.class.getName()
                            : RegistrationEmailTemplate.class.getName());
        sm.setMessagePrefix(mailPrefix);
        sm.setEmailTemplate((SecurityEmailTemplate)et);
        sm.setType("User Registration Email");

        return sm;
    }

    public static SecurityMessage getResetMessage(boolean isAdminCopy) throws Exception
    {
        SecurityMessage sm = new SecurityMessage();

        EmailTemplate et = EmailTemplateService.get().getEmailTemplate(
                isAdminCopy ? PasswordResetAdminEmailTemplate.class.getName()
                            : PasswordResetEmailTemplate.class.getName());
        sm.setEmailTemplate((SecurityEmailTemplate)et);
        sm.setType("Reset Password Email");
        return sm;
    }

    /**
     * @return null if the user already existed, or a message indicating success/failure
     */
    public static String addUser(ViewContext context, ValidEmail email, boolean sendMail, String mailPrefix, Pair<String, String>[] extraParameters) throws Exception
    {
        if (SecurityManager.loginExists(email))
        {
            return null;
        }

        StringBuilder message = new StringBuilder();
        NewUserBean newUserBean;

        String mailContentURL = null;
        boolean appendClickToSeeMail = false;
        User currentUser = context.getUser();

        try
        {
            newUserBean = SecurityManager.addUser(email);

            if (!newUserBean.isLdap() && sendMail)
            {
                ActionURL actionURL = new ActionURL("Security", "showRegistrationEmail", context.getContainer());
                actionURL.addParameter("email", email.getEmailAddress());
                actionURL.addParameter("mailPrefix", mailPrefix);
                mailContentURL = actionURL.getLocalURIString();

                String verificationUrl = SecurityManager.createVerificationUrl(context.getContainer(), email.getEmailAddress(),
                        newUserBean.getVerification(), extraParameters).getURIString();

                SecurityManager.sendEmail(currentUser, getRegistrationMessage(mailPrefix, false),
                        email.getEmailAddress(), verificationUrl);
                if (!currentUser.getEmail().equals(email.getEmailAddress()))
                {
                    SecurityMessage msg = getRegistrationMessage(mailPrefix, true);
                    msg.setTo(email.getEmailAddress());
                    SecurityManager.sendEmail(currentUser, msg, currentUser.getEmail(), verificationUrl);
                }
                appendClickToSeeMail = true;
            }

            User newUser = newUserBean.getUser();

            if (newUserBean.isLdap())
            {
                message.append(newUser.getEmail()).append(" added as a new user to the system.  This user will be authenticated via LDAP.");
                UserManager.addToUserHistory(newUser, newUser.getEmail() + " was added to the system.  This user will be authenticated via LDAP.");
            }
            else if (sendMail)
            {
                message.append(email.getEmailAddress()).append(" added as a new user to the system and emailed successfully.");
                UserManager.addToUserHistory(newUser, newUser.getEmail() + " was added to the system.  Verification email was sent successfully.");
            }
            else
            {
                String href = "<a href=\"" + SecurityManager.createVerificationUrl(context.getContainer(),
                        email.getEmailAddress(), newUserBean.getVerification(), extraParameters).getURIString() + "\" target=\"" + email.getEmailAddress() + "\">here</a>";
                message.append(email.getEmailAddress()).append(" added as a new user to the sytem, but no email was sent.  Click ");
                message.append(href).append(" to change the password from the random one that was assigned.");
                UserManager.addToUserHistory(newUser, newUser.getEmail() + " was added to the system and the administrator chose not to send a verification email.");
            }
        }
        catch (MessagingException e)
        {
            message.append("<br>");
            message.append(email.getEmailAddress());
            message.append(" was added successfully, but could not be emailed due to a failure:<br><pre>");
            message.append(e.getMessage());
            message.append("</pre>");
            appendMailHelpText(message, mailContentURL);

            User newUser = UserManager.getUser(email);

            if (null != newUser)
                UserManager.addToUserHistory(newUser, newUser.getEmail() + " was added to the system.  Sending the verification email failed.");
        }
        catch (SecurityManager.UserAlreadyExistsException e)
        {
            return null;
        }
        catch (SecurityManager.UserManagementException e)
        {
            message.append("Failed to create user ").append(email).append(": ").append(e.getMessage());
        }

        if (appendClickToSeeMail && mailContentURL != null)
        {
            String href = "<a href=" + mailContentURL + " target=\"_blank\">here</a>";
            message.append(" Click ").append(href).append(" to see the email.");
        }

        return message.toString();
    }

    private static void appendMailHelpText(StringBuilder sb, String mailHref)
    {
        sb.append("You can attempt to resend this mail later by going to the Site Users link, clicking on the appropriate user from the list, and resetting their password.");
        if (mailHref != null)
        {
            sb.append(" Alternatively, you can copy the <a href=\"");
            sb.append(mailHref);
            sb.append("\" target=\"_blank\">contents of the message</a> into an email client and send it to the user manually.");
        }
        sb.append("</p>");
        sb.append("<p>For help on fixing your mail server settings, please consult the SMTP section of the <a href=\"");
        sb.append((new HelpTopic("cpasxml", HelpTopic.Area.SERVER)).getHelpTopicLink());
        sb.append("\" target=\"_blank\">LabKey documentation on modifying your configuration file</a>.<br>");
    }


    public static void createNewProjectGroups(Container project)
    {
        /*
        this check doesn't work well when moving container
        if (!project.isProject())
            throw new IllegalArgumentException("Must be a top level container");
        */

        // Create default groups
        Group adminGroup = SecurityManager.createGroup(project, "Administrators");
        Group userGroup = SecurityManager.createGroup(project, "Users");

        // Set default permissions
        // CONSIDER: get/set permissions on Container, rather than going behind its back
        ACL acl = new ACL();
        acl.setPermission(Group.groupAdministrators, ACL.PERM_ALLOWALL);
        if (null != adminGroup)
            acl.setPermission(adminGroup, ACL.PERM_ALLOWALL);
        if (null != userGroup)
            acl.setPermission(userGroup, ACL.PERM_NONE);

        // Set logged in users and guests to have no permissions on new projects by default
        acl.setPermission(Group.groupUsers, 0);
        acl.setPermission(Group.groupGuests, 0);

        SecurityManager.updateACL(project, acl);
    }

    public static void setAdminOnlyPermissions(Container c)
    {
        ACL acl = new ACL();
        acl.setPermission(Group.groupAdministrators, ACL.PERM_ALLOWALL);
        Integer administratorsGroupId = getGroupId(c.getProject(), "Administrators", false);
        if (null != administratorsGroupId && 0 != administratorsGroupId)
            acl.setPermission(administratorsGroupId, ACL.PERM_ALLOWALL);

        updateACL(c, acl);
    }

    public static boolean isAdminOnlyPermissions(Container c)
    {
        ACL acl = c.getAcl(); //NOTE: Could be  inherited, but we don't care...
        Integer administratorsGroupInteger = getGroupId(c.getProject(), "Administrators", false);
        int adminGroupId = null != administratorsGroupInteger ? administratorsGroupInteger.intValue() : Group.groupAdministrators;
        boolean adminOnly = true;
        for (int groupId : acl._groups)
            if (groupId != Group.groupAdministrators && groupId != adminGroupId)
            {
                adminOnly = false;
                break;
            }

        return adminOnly;
    }

    public static void setInheritPermissions(Container c)
    {
        removeACL(c, c.getId()); //Inherit permissions        
    }

    private static final String SUBFOLDERS_INHERIT_PERMISSIONS_NAME = "SubfoldersInheritPermissions";
    
    public static boolean shouldNewSubfoldersInheritPermissions(Container project)
    {
        Map<String, String> props = PropertyManager.getProperties(project.getId(), SUBFOLDERS_INHERIT_PERMISSIONS_NAME, false);
        boolean subfoldersInherit = props != null && "true".equals(props.get(SUBFOLDERS_INHERIT_PERMISSIONS_NAME));
        return subfoldersInherit;
    }

    public static void setNewSubfoldersInheritPermissions(Container project, boolean inherit)
    {
        Map<String, String> props = PropertyManager.getWritableProperties(project.getId(), SUBFOLDERS_INHERIT_PERMISSIONS_NAME, true);
        props.put(SUBFOLDERS_INHERIT_PERMISSIONS_NAME, Boolean.toString(inherit));
        PropertyManager.saveProperties(props);
    }


    public static void changeProject(Container c, Container oldProject, Container newProject)
            throws SQLException
    {
        assert core.getSchema().getScope().isTransactionActive();

        if (oldProject.getId().equals(newProject.getId()))
            return;

        /* when demoting a project to a regular folder, delete the project groups */
        if (oldProject == c)
        {
            org.labkey.api.security.SecurityManager.deleteGroups(c,Group.typeProject);
        }

        /*
         * Clear all ACLS for folders that changed project!
         */
        Container[] subtrees = ContainerManager.getAllChildren(c);
        StringBuilder sb = new StringBuilder();
        String comma = "";
        for (Container sub : subtrees)
        {
            sb.append(comma);
            sb.append("'");
            sb.append(sub.getId());
            sb.append("'");
            comma = ",";
        }
        Table.execute(core.getSchema(), "DELETE FROM " + core.getTableInfoACLs() + "\n" +
            "WHERE Container IN (" + sb.toString() + ")", null);
        DbCache.clear(core.getTableInfoACLs());

        /* when promoting a folder to a project, create default project groups */
        if (newProject == c)
        {
            createNewProjectGroups(c);
        }
    }

    public abstract static class SecurityEmailTemplate extends EmailTemplate
    {
        protected String _optionalPrefix;
        protected boolean _hideContact;
        private String _verificationUrl = "";
        private String _emailAddress = "";
        private String _recipient = "";
        protected boolean _verificationUrlRequired = true;
        private List<ReplacementParam> _replacements = new ArrayList<ReplacementParam>();

        protected SecurityEmailTemplate(String name)
        {
            super(name);

            _replacements.add(new ReplacementParam("verificationURL", "Link for a user to set a password"){
                public String getValue() {return _verificationUrl;}
            });
            _replacements.add(new ReplacementParam("emailAddress", "The email address of the user performing the operation"){
                public String getValue() {return _emailAddress;}
            });
            _replacements.add(new ReplacementParam("recipient", "The email address on the 'to:' line"){
                public String getValue() {return _recipient;}
            });
            _replacements.addAll(super.getValidReplacements());
        }

        public void setOptionPrefix(String optionalPrefix){_optionalPrefix = optionalPrefix;}
        public void setHideContact(boolean hideContact){_hideContact = hideContact;}
        public void setVerificationUrl(String verificationUrl){_verificationUrl = verificationUrl;}
        public void setEmailAddress(String emailAddress){_emailAddress = emailAddress;}
        public void setRecipient(String recipient){_recipient = recipient;}
        public List<ReplacementParam> getValidReplacements(){return _replacements;}

        public boolean isValid(String[] error)
        {
            if (super.isValid(error))
            {
                // add an additional requirement for the verification url
                if (!_verificationUrlRequired || getBody().indexOf("%verificationURL%") != -1)
                {
                    return true;
                }
                error[0] = "The substitution param: %verificationURL% is required to be somewhere in the body of the message";
            }
            return false;
        }
    }

    public static class RegistrationEmailTemplate extends SecurityEmailTemplate
    {
        protected static final String DEFAULT_SUBJECT =
                "Welcome to the %organizationName% %siteShortName% Web Site new user registration";
        protected static final String DEFAULT_BODY =
                "You now have an account on the %organizationName% %siteShortName% web site.  We are sending " +
                "you this message to verify your email address and to allow you to create a password that will provide secure " +
                "access to your data on the web site.  To complete the registration process, simply click the link below or " +
                "copy it to your browser's address bar.  You will then be asked to choose a password.\n\n" +
                "%verificationURL%\n\n" +
                "Note: The link above should appear on one line, starting with 'http' and ending with your email address.  Some " +
                "email systems may break this link into multiple lines, causing the verification to fail.  If this happens, " +
                "you'll need to paste the parts into the address bar of your browser to form the full link.\n\n" +
                "The %siteShortName% home page is %homePageURL%.  When you visit the home page " +
                "and log in with your new password you will see a list of projects on the left side of the page.  Click those " +
                "links to visit your projects.\n\n" +
                "If you have any questions don't hesitate to contact the %siteShortName% team at %emailAddress%.";

        public RegistrationEmailTemplate()
        {
            super("Register new user");
            setSubject(DEFAULT_SUBJECT);
            setBody(DEFAULT_BODY);
            setDescription("Sent to the new user and administrator when a user is added to the site.");
            setPriority(1);
        }

        public String renderBody()
        {
            StringBuffer sb = new StringBuffer();

            if (_optionalPrefix != null)
            {
                sb.append(_optionalPrefix);
                sb.append("\n\n");
            }
            return sb.append(super.renderBody()).toString();
        }
    }

    public static class RegistrationAdminEmailTemplate extends RegistrationEmailTemplate
    {
        public RegistrationAdminEmailTemplate()
        {
            super();
            setName("Register new user (bcc to admin)");
            setSubject("%recipient% : " + DEFAULT_SUBJECT);
            setBody("The following message was sent to %recipient% :\n\n" + DEFAULT_BODY);
            setPriority(2);
            _verificationUrlRequired = false;
        }
    }

    public static class PasswordResetEmailTemplate extends SecurityEmailTemplate
    {
        private static final String CONTACT_STRING = "\n\nIf you have any questions don't hesitate to contact the %siteShortName% team at %emailAddress%.";
        protected static final String DEFAULT_SUBJECT =
                "Reset Password Notification from the %siteShortName% Web Site";
        protected static final String DEFAULT_BODY =
                "We have reset your password on the %organizationName% %siteShortName% web site. " +
                "To sign in to the system you will need " +
                "to specify a new password.  Click the link below or copy it to your browser's address bar.  You will then be " +
                "asked to enter a new password.\n\n" +
                "%verificationURL%\n\n" +
                "The %siteShortName% home page is %homePageURL%.  When you visit the home page and log " +
                "in with your new password you will see a list of projects on the left side of the page.  Click those links to " +
                "visit your projects.";

        public PasswordResetEmailTemplate()
        {
            super("Reset password");
            setSubject(DEFAULT_SUBJECT);
            setBody(DEFAULT_BODY);
            setDescription("Sent to the user and administrator when the password of a user is reset.");
            setPriority(3);
        }

        public String renderBody()
        {
            StringBuffer sb = new StringBuffer(super.renderBody());
            if (!_hideContact)
                sb.append(render(CONTACT_STRING));

            return sb.toString();
        }
    }

    public static class PasswordResetAdminEmailTemplate extends PasswordResetEmailTemplate
    {
        public PasswordResetAdminEmailTemplate()
        {
            super();
            setName("Reset password (bcc to admin)");
            setSubject("%recipient% : " + DEFAULT_SUBJECT);
            setBody("The following message was sent to %recipient% :\n\n" + DEFAULT_BODY);
            setPriority(4);
            _verificationUrlRequired = false;
        }
    }
}
