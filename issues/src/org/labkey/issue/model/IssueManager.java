/*
 * Copyright (c) 2005-2015 Fred Hutchinson Cancer Research Center
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
package org.labkey.issue.model;

import org.apache.commons.beanutils.ConversionException;
import org.apache.commons.collections15.comparators.ReverseComparator;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.labkey.api.cache.CacheLoader;
import org.labkey.api.cache.StringKeyCache;
import org.labkey.api.collections.ResultSetRowMapFactory;
import org.labkey.api.data.Container;
import org.labkey.api.data.ContainerManager;
import org.labkey.api.data.CoreSchema;
import org.labkey.api.data.DatabaseCache;
import org.labkey.api.data.DbScope;
import org.labkey.api.data.Filter;
import org.labkey.api.data.ObjectFactory;
import org.labkey.api.data.PropertyManager;
import org.labkey.api.data.RuntimeSQLException;
import org.labkey.api.data.SQLFragment;
import org.labkey.api.data.Selector;
import org.labkey.api.data.SimpleFilter;
import org.labkey.api.data.Sort;
import org.labkey.api.data.SqlExecutor;
import org.labkey.api.data.SqlSelector;
import org.labkey.api.data.Table;
import org.labkey.api.data.TableInfo;
import org.labkey.api.data.TableSelector;
import org.labkey.api.issues.IssuesSchema;
import org.labkey.api.query.FieldKey;
import org.labkey.api.search.SearchService;
import org.labkey.api.search.SearchService.IndexTask;
import org.labkey.api.security.Group;
import org.labkey.api.security.MemberType;
import org.labkey.api.security.SecurityManager;
import org.labkey.api.security.User;
import org.labkey.api.security.UserDisplayNameComparator;
import org.labkey.api.security.UserManager;
import org.labkey.api.security.ValidEmail;
import org.labkey.api.security.permissions.AdminPermission;
import org.labkey.api.security.permissions.InsertPermission;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.services.ServiceRegistry;
import org.labkey.api.util.ContainerUtil;
import org.labkey.api.util.FileStream;
import org.labkey.api.util.JunitUtil;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.Path;
import org.labkey.api.util.TestContext;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.AjaxCompletion;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.JspView;
import org.labkey.api.view.ViewContext;
import org.labkey.api.view.ViewServlet;
import org.labkey.api.webdav.AbstractDocumentResource;
import org.labkey.api.webdav.WebdavResource;
import org.labkey.issue.ColumnType;
import org.labkey.issue.IssuesController;

import javax.servlet.ServletException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.labkey.api.search.SearchService.PROPERTY.categories;

/**
 * User: mbellew
 * Date: Mar 11, 2005
 * Time: 11:07:27 AM
 */
public class IssueManager
{
    public static final SearchService.SearchCategory searchCategory = new SearchService.SearchCategory("issue", "Issues");
    // UNDONE: Keywords, Summary, etc.

    private static IssuesSchema _issuesSchema = IssuesSchema.getInstance();
    
    public static final int NOTIFY_ASSIGNEDTO_OPEN = 1;     // if a bug is assigned to me
    public static final int NOTIFY_ASSIGNEDTO_UPDATE = 2;   // if a bug assigned to me is modified
    public static final int NOTIFY_CREATED_UPDATE = 4;      // if a bug I created is modified
    public static final int NOTIFY_SUBSCRIBE = 16;           // send email on all changes

    public static final int NOTIFY_SELF_SPAM = 8;           // spam me when I enter/edit a bug
    public static final int DEFAULT_EMAIL_PREFS = NOTIFY_ASSIGNEDTO_OPEN | NOTIFY_ASSIGNEDTO_UPDATE | NOTIFY_CREATED_UPDATE;

    private static final String ISSUES_PREF_MAP = "IssuesPreferencesMap";
    private static final String ISSUES_REQUIRED_FIELDS = "IssuesRequiredFields";

    private static final String CAT_ENTRY_TYPE_NAMES = "issueEntryTypeNames";
    private static final String PROP_ENTRY_TYPE_NAME_SINGULAR = "issueEntryTypeNameSingular";
    private static final String PROP_ENTRY_TYPE_NAME_PLURAL = "issueEntryTypeNamePlural";

    private static final String CAT_ASSIGNED_TO_LIST = "issueAssignedToList";
    private static final String PROP_ASSIGNED_TO_GROUP = "issueAssignedToGroup";

    private static final String CAT_DEFAULT_ASSIGNED_TO_LIST = "issueDefaultAsignedToList";
    private static final String PROP_DEFAULT_ASSIGNED_TO_USER = "issueDefaultAssignedToUser";

    private static final String CAT_DEFAULT_MOVE_TO_LIST = "issueDefaultMoveToList";
    private static final String PROP_DEFAULT_MOVE_TO_CONTAINER = "issueDefaultMoveToContainer";

    private static final String CAT_DEFAULT_INHERIT_FROM_CONTAINER = "issueDefaultInheritFromCategory";
    private static final String PROP_DEFAULT_INHERIT_FROM_CONTAINER = "issueDefaultInheritFromProperty";

    private static final String CAT_DEFAULT_RELATED_ISSUES_LIST = "issueRelatedIssuesList";
    private static final String PROP_DEFAULT_RELATED_ISSUES_LIST = "issueRelatedIssuesList";

    private static final String CAT_COMMENT_SORT = "issueCommentSort";
    public static final String PICK_LIST_NAME = "pickListColumns";

    private IssueManager()
    {
    }

    /**
     * Identifies whether the (Issue List) admin settings of container c were inherited by other containers.
     * Example: Folder_B has inherited it's admin settings from Folder_A. If param c is Folder_A, then this
     * method will return true, since Folder_B has inherited admin settings from Folder_A.
     * @param c
     * @return  true if (one) container with inherited settings from c was found, false otherwise.
     */
    public static boolean hasInheritingContainers(@NotNull Container c)
    {

        for(Container possibleInheritor :  ContainerManager.getAllChildren(ContainerManager.getRoot()))
        {
            Map<String, String> props = PropertyManager.getProperties(possibleInheritor, CAT_DEFAULT_INHERIT_FROM_CONTAINER);
            String propsValue = props.get(PROP_DEFAULT_INHERIT_FROM_CONTAINER);

            if(propsValue != null && c.getId().equals(propsValue))
                return true;
        }

        return false;
    }

    public static Issue getIssue(@Nullable Container c, int issueId)
    {
        SimpleFilter f = new SimpleFilter(FieldKey.fromParts("issueId"), issueId);
        if (null != c)
            f.addCondition(FieldKey.fromParts("container"), c);

        TableSelector selector = new TableSelector(_issuesSchema.getTableInfoIssues(), f, null);
        selector.setForDisplay(true);
        Issue issue = selector.getObject(Issue.class);
        if (issue == null)
            return null;

        List<Issue.Comment> comments = new TableSelector(_issuesSchema.getTableInfoComments(),
                new SimpleFilter(FieldKey.fromParts("issueId"), issue.getIssueId()),
                new Sort("CommentId")).getArrayList(Issue.Comment.class);
        issue.setComments(comments);

        Collection<Integer> dups = new TableSelector(_issuesSchema.getTableInfoIssues().getColumn("IssueId"),
                new SimpleFilter(FieldKey.fromParts("Duplicate"), issueId),
                new Sort("IssueId")).getCollection(Integer.class);
        issue.setDuplicates(dups);

        Collection<Integer> rels = new TableSelector(_issuesSchema.getTableInfoRelatedIssues().getColumn("RelatedIssueId"),
                new SimpleFilter(FieldKey.fromParts("IssueId"), issueId),
                new Sort("IssueId")).getCollection(Integer.class);

        issue.setRelatedIssues(rels);
        // the related string is only used when rendering the update form
        issue.setRelated(StringUtils.join(rels, ", "));
        return issue;
    }

    /**
     * Returns a linked list of all comments for the argument Issue together with comments
     * of all related issues sorted by creation date.
     *
     * @param   issue   an issue to retrieve comments from
     * @return          the sorted linked list of all related comments
     */
    public static List<Issue.Comment> getCommentsForRelatedIssues(Issue issue, User user)
    {
        // Get related issues for optional display
        Set<Integer> relatedIssues = issue.getRelatedIssues();
        List<Issue.Comment> commentLinkedList = new LinkedList<>();

        // Add related issue comments
        for (Integer relatedIssueInt : relatedIssues)
        {
            // only add related issues that the user has permission to see
            Issue relatedIssue = IssueManager.getIssue(null, relatedIssueInt);
            if (relatedIssue != null)
            {
                boolean hasReadPermission = ContainerManager.getForId(relatedIssue.getContainerId()).hasPermission(user, ReadPermission.class);
                if (hasReadPermission)
                    commentLinkedList.addAll(relatedIssue.getComments());
            }
        }
        // Add all current issue comments
        commentLinkedList.addAll(issue.getComments());

        Comparator<Issue.Comment> comparator = (c1, c2) -> c1.getCreated().compareTo(c2.getCreated());
        // Respect the configuration's sorting order - issue 23524
        Container issueContainer = issue.lookupContainer();
        if (Sort.SortDirection.DESC == getCommentSortDirection(issueContainer))
        {
            comparator = new ReverseComparator<>(comparator);
        }

        Collections.sort(commentLinkedList, comparator);
        return commentLinkedList;
    }

    /**
     * Determine if the parameter issue has related issues.  Returns true if the issue has related
     * issues and false otherwise.
     *
     * @param   issue   The issue to query
     * @return          boolean return value
     */
    public static boolean hasRelatedIssues(Issue issue, User user)
    {
        for (Integer relatedIssueInt : issue.getRelatedIssues())
        {
            Issue relatedIssue = IssueManager.getIssue(null, relatedIssueInt);
            if (relatedIssue != null && relatedIssue.getComments().size() > 0)
            {
                boolean hasReadPermission = ContainerManager.getForId(relatedIssue.getContainerId()).hasPermission(user, ReadPermission.class);
                if (hasReadPermission)
                    return true;
            }
        }
        return false;
    }

    public static void saveIssue(User user, Container c, Issue issue) throws SQLException
    {
        if (issue.assignedTo == null)
            issue.assignedTo = 0;

        if (issue.issueId == 0)
        {
            issue.beforeInsert(user, c.getId());
            Table.insert(user, _issuesSchema.getTableInfoIssues(), issue);
        }
        else
        {
            issue.beforeUpdate(user);
            Table.update(user, _issuesSchema.getTableInfoIssues(), issue, issue.getIssueId());
        }
        saveComments(user, issue);
        saveRelatedIssues(user, issue);

        indexIssue(null, issue);
    }


    protected static void saveComments(User user, Issue issue) throws SQLException
    {
        Collection<Issue.Comment> comments = issue._added;
        if (null == comments)
            return;
        for (Issue.Comment comment : comments)
        {
            // NOTE: form has already validated comment text, but let's be extra paranoid.
            if (!ViewServlet.validChars(comment.getComment()))
                throw new ConversionException("comment has invalid characters");

            Map<String, Object> m = new HashMap<>();
            m.put("issueId", issue.getIssueId());
            m.put("comment", comment.getComment());
            m.put("entityId", comment.getEntityId());
            Table.insert(user, _issuesSchema.getTableInfoComments(), m);
        }
        issue._added = null;
    }

    protected static void saveRelatedIssues(User user, Issue issue) throws SQLException
    {
        Collection<Integer> rels = issue.getRelatedIssues();

        int issueId = issue.getIssueId();

        Table.delete(_issuesSchema.getTableInfoRelatedIssues(), new SimpleFilter(FieldKey.fromParts("IssueId"), issueId));

        for (Integer rel : rels)
        {
            Map<String, Object> m = new HashMap<>();
            m.put("issueId", issueId);
            m.put("relatedIssueId", rel);
            Table.insert(user, _issuesSchema.getTableInfoRelatedIssues(), m);
        }
    }


    public static Map<ColumnType, String> getAllDefaults(Container container) throws SQLException
    {
        final Map<ColumnType, String> defaults = new HashMap<>();
        SimpleFilter filter = SimpleFilter.createContainerFilter(container).addCondition(FieldKey.fromParts("Default"), true);
        Selector selector = new TableSelector(_issuesSchema.getTableInfoIssueKeywords(), PageFlowUtil.set("Type", "Keyword", "Container", "Default"), filter, null);

        selector.forEach(new Selector.ForEachBlock<ResultSet>() {
            @Override
            public void exec(ResultSet rs) throws SQLException
            {
                ColumnType type = ColumnType.forOrdinal(rs.getInt("Type"));

                assert null != type;

                if (null != type)
                    defaults.put(type,rs.getString("Keyword"));
            }
        });

        return defaults;
    }


    public static CustomColumnConfiguration getCustomColumnConfiguration(Container c)
    {
        return ColumnConfigurationCache.get(c);
    }


    public static class CustomColumn
    {
        private Container _container;
        private String _name;
        private String _caption;
        private boolean _pickList;
        private Class<? extends Permission> _permissionClass;
        private boolean _inherited;

        // Used via reflection by data access layer
        @SuppressWarnings({"UnusedDeclaration"})
        public CustomColumn()
        {
        }

        public CustomColumn(Container container, String name, String caption, boolean pickList, Class<? extends Permission> permissionClass)
        {
            setContainer(container);
            setName(name);
            setCaption(caption);
            setPickList(pickList);
            setPermission(permissionClass);
        }

        public Container getContainer()
        {
            return _container;
        }

        public void setContainer(Container container)
        {
            _container = container;
        }

        public String getName()
        {
            return _name;
        }

        public void setName(String name)
        {
            assert name.equals(name.toLowerCase());
            _name = name;
        }

        public String getCaption()
        {
            return _caption;
        }

        public void setCaption(String caption)
        {
            _caption = caption;
        }

        public boolean isPickList()
        {
            return _pickList;
        }

        public void setPickList(boolean pickList)
        {
            _pickList = pickList;
        }

        public Class<? extends Permission> getPermission()
        {
            return _permissionClass;
        }

        public void setPermission(Class<? extends Permission> permissionClass)
        {
            _permissionClass = permissionClass;
        }

        public boolean hasPermission(User user)
        {
            return _container.hasPermission(user, _permissionClass);
        }

        public void setInherited(boolean isInherited)
        {
            _inherited = isInherited ;
        }

        public boolean isInherited()
        {
            return _inherited;
        }
    }

    static class CustomColumnMap extends LinkedHashMap<String, CustomColumn>
    {
        private CustomColumnMap(Map<String, CustomColumn> map)
        {
            // Copy the map ensuring the canonical order specified by COLUMN_NAMES
            for (String name : CustomColumnConfiguration.COLUMN_NAMES)
            {
                CustomColumn cc = map.get(name);

                if (null != cc)
                    put(name, cc);
            }
        }
    }


    // Delete all old rows and insert the new rows; we don't bother detecting changes because this operation should be infrequent.
    public static void saveCustomColumnConfiguration(Container c, CustomColumnConfiguration ccc)
    {
        TableInfo table = IssuesSchema.getInstance().getTableInfoCustomColumns();
        Filter filter = new SimpleFilter(new FieldKey(null, "Container"), c);

        try (DbScope.Transaction transaction = table.getSchema().getScope().ensureTransaction())
        {
            Table.delete(table, filter);

            for (CustomColumn cc : ccc.getCustomColumns())
                Table.insert(null, table, cc);

            transaction.commit();
        }
        finally
        {
            ColumnConfigurationCache.uncache();
        }
    }


    public static class CustomColumnConfiguration
    {
        private static final String[] COLUMN_NAMES = {"type", "area", "priority", "milestone", "resolution", "related", "int1", "int2", "string1", "string2", "string3", "string4", "string5"};

        private final CustomColumnMap _map;

        // Values are being loaded from the database
        public CustomColumnConfiguration(@NotNull Map<String, CustomColumn> map, Container c)
        {

            Container inheritFrom = getInheritFromContainer(c); //get the container from which c inherited it's admin settings from


            //Merge non-conflicting Custom Column values for Integer1, Integer2, String 1 to String 5 if inheriting.
            //Non-conflicting custom column values are values such that container c and inheritFrom are
            //not occupying the same Custom Column.
            if(inheritFrom != null)
            {
                //Simply iterating through the map and using remove() throws java.util.ConcurrentModificationException.
                // Hence, using a iterator to avoid this exception.
                Iterator<Map.Entry<String, CustomColumn>> iter = map.entrySet().iterator();

                while(iter.hasNext())
                {
                    Map.Entry<String, CustomColumn> col = iter.next();
                    String colName = col.getKey();

                    //Remove any pre-exisiting values for these six custom columns of the current container
                    //to be able to inherit these from inheritFrom container, even if empty.
                    //Rationale: Enabling to modify these custom col fields if not inherited, would also
                    //modify the name in the 'Keyword' section/Options section (last/bottom section of the Admin page).
                    //For example: user inherits 'Type Options' in the Keyword section, and 'Type' under
                    // 'Custom Column' is enabled, allowing to add a custom field value for 'Type' will
                    // modify 'Type Options' to '<User defined Type name> Options' (in the Keyword section).
                    if(colName != null && (colName.equals(ColumnType.TYPE) || colName.equals(ColumnType.AREA)
                            || colName.equals(ColumnType.PRIORITY) || colName.equals(ColumnType.MILESTONE)
                            || colName.equals(ColumnType.RESOLUTION) || colName.equals(ColumnType.RELATED)))
                    {
                        iter.remove();
                    }
                }

                CustomColumnConfiguration inheritFromCCC = getCustomColumnConfiguration(inheritFrom);
                Collection<CustomColumn> inheritFromCC = inheritFromCCC.getCustomColumns();

                for(CustomColumn cc : inheritFromCC)
                {
                    //override with inheritFrom container
                    map.put(cc.getName(), cc);
                }
            }

            _map = new CustomColumnMap(map);
        }

        // Values are being posted from the admin page
        public CustomColumnConfiguration(ViewContext context)
        {
            Container c = context.getContainer();
            Map<String, Object> map = context.getExtendedProperties();

            // Could be null, a single String, or List<String>
            Object pickList = map.get(PICK_LIST_NAME);

            Set<String> pickListColumnNames;

            if (null == pickList)
                pickListColumnNames = Collections.emptySet();
            else if (pickList instanceof String)
                pickListColumnNames = Collections.singleton((String)pickList);
            else
                pickListColumnNames = new HashSet<>((List<String>)pickList);

            //need a better way to do this. this code assumes that permissions are listed as per string values: string1 will have permission in 0 location in the list, etc.
            // what if string1 and string2 are inherited? then string3-string5 values are now listed in the perms.
            List<String> perms = context.getList("permissions");

            int totalCustomColsWithPerms = 5;
            // Should have one for each string column (we don't support permissions on int columns yet)
            assert perms.size() <= totalCustomColsWithPerms; //if custom column values are inherited from a different container, then perms.size() can be less than 5.
            Map<String, Class<? extends Permission>> permMap = new HashMap<>();

            int index = 0;//perms index counter

            for (int i = 0; i < totalCustomColsWithPerms; i++)
            {
                String stringCustCol = "string" + (i + 1);
                String stringCustColVal = (String) map.get(stringCustCol); //look for non-inherited custom strings (only non-inherited strings will be captured in the context map).

                //if custom string is not empty
                if(StringUtils.isNotEmpty(stringCustColVal))
                {
                    //get custom string column's permission, which should be listed in a list starting from index 0. For example: first non-inherited custom string (say, string3) will have it's permission value in index 0.
                    String simplePerm = perms.get(index);

                    Class<? extends Permission> perm = "admin".equals(simplePerm) ? AdminPermission.class : "insert".equals(simplePerm) ? InsertPermission.class : ReadPermission.class;
                    permMap.put(stringCustCol, perm);
                    index++;
                }
            }

            Map<String, CustomColumn> ccMap = new HashMap<>();

            for (String columnName : COLUMN_NAMES)
            {
                String caption = (String)map.get(columnName);

                if (!StringUtils.isEmpty(caption))
                {
                    Class<? extends Permission> perm = permMap.get(columnName);
                    CustomColumn cc = new CustomColumn(c, columnName, caption, pickListColumnNames.contains(columnName), null != perm ? perm : ReadPermission.class);
                    ccMap.put(columnName, cc);
                }
            }

            _map = new CustomColumnMap(ccMap);
        }

        public CustomColumn getCustomColumn(String name)
        {
            return _map.get(name);
        }

        @Deprecated
        public Collection<CustomColumn> getCustomColumns()
        {
            return _map.values();
        }

        public Collection<CustomColumn> getCustomColumns(User user)
        {
            List<CustomColumn> list = new LinkedList<>();

            for (CustomColumn customColumn : _map.values())
                if (customColumn.hasPermission(user))
                    list.add(customColumn);

            return list;
        }

        @Deprecated
        public boolean shouldDisplay(String name)
        {
            return _map.containsKey(name);
        }

        public boolean shouldDisplay(User user, String name)
        {
            CustomColumn cc = getCustomColumn(name);

            return null != cc && cc.getContainer().hasPermission(user, cc.getPermission());
        }

        public boolean hasPickList(String name)
        {
            CustomColumn cc = getCustomColumn(name);

            return null != cc && cc.isPickList();
        }

        public @Nullable String getCaption(String name)
        {
            CustomColumn cc = getCustomColumn(name);

            return null != cc ? cc.getCaption() : null;
        }

        // TODO: If we need this, then pre-compute it
        public Map<String, String> getColumnCaptions()
        {
            Map<String, String> map = new HashMap<>();

            for (CustomColumn cc : _map.values())
                map.put(cc.getName(), cc.getCaption());

            return map;
        }
    }


    public static Map[] getSummary(Container c) throws SQLException
    {
        SQLFragment sql = new SQLFragment("SELECT DisplayName, SUM(CASE WHEN Status='open' THEN 1 ELSE 0 END) AS " +
            _issuesSchema.getSqlDialect().makeLegalIdentifier("Open") + ", SUM(CASE WHEN Status='resolved' THEN 1 ELSE 0 END) AS " +
            _issuesSchema.getSqlDialect().makeLegalIdentifier("Resolved") + "\n" +
            "FROM " + _issuesSchema.getTableInfoIssues() + " LEFT OUTER JOIN " + CoreSchema.getInstance().getTableInfoUsers() +
            " ON AssignedTo = UserId\n" +
                "WHERE Status in ('open', 'resolved') AND Container = ?\n" +
                "GROUP BY DisplayName",
                c.getId());

        return new SqlSelector(_issuesSchema.getSchema(), sql).getMapArray();
    }


    private static final Comparator<User> USER_COMPARATOR = new UserDisplayNameComparator();

    public static @NotNull Collection<User> getAssignedToList(Container c, Issue issue)
    {
        Collection<User> initialAssignedTo = getInitialAssignedToList(c);

        // If this is an existing issue, add the user who opened the issue, unless they are a guest, inactive, already in the list, or don't have permissions.
        if (issue != null && 0 != issue.getIssueId())
        {
            User createdByUser = UserManager.getUser(issue.getCreatedBy());

            if (createdByUser != null && !createdByUser.isGuest() && !initialAssignedTo.contains(createdByUser) && canAssignTo(c, createdByUser))
            {
                Set<User> modifiedAssignedTo = new TreeSet<>(USER_COMPARATOR);
                modifiedAssignedTo.addAll(initialAssignedTo);
                modifiedAssignedTo.add(createdByUser);
                return Collections.unmodifiableSet(modifiedAssignedTo);
            }
        }

        return initialAssignedTo;
    }


    private static final StringKeyCache<Set<User>> ASSIGNED_TO_CACHE = new DatabaseCache<>(IssuesSchema.getInstance().getSchema().getScope(), 1000, "AssignedTo");

    // Returns the assigned to list that is used for every new issue in this container.  We can cache it and share it
    // across requests.  The collection is unmodifiable.
    private static @NotNull Collection<User> getInitialAssignedToList(final Container c)
    {
        String cacheKey = getCacheKey(c);

        return ASSIGNED_TO_CACHE.get(cacheKey, null, new CacheLoader<String, Set<User>>() {
            @Override
            public Set<User> load(String key, @Nullable Object argument)
            {
                Group group = getAssignedToGroup(c);

                if (null != group)
                    return createAssignedToList(c, SecurityManager.getAllGroupMembers(group, MemberType.ACTIVE_USERS, true));
                else
                    return createAssignedToList(c, SecurityManager.getProjectUsers(c.getProject()));
            }
        });
    }


    public static String getCacheKey(@Nullable Container c)
    {
        String key = "AssignedTo";
        return null != c ? key + c.getId() : key;
    }


    private static Set<User> createAssignedToList(Container c, Collection<User> candidates)
    {
        Set<User> assignedTo = new TreeSet<>(USER_COMPARATOR);

        for (User candidate : candidates)
            if (canAssignTo(c, candidate))
                assignedTo.add(candidate);

        // Cache an unmodifiable version
        return Collections.unmodifiableSet(assignedTo);
    }


    private static boolean canAssignTo(Container c, @NotNull User user)
    {
        return user.isActive() && c.hasPermission(user, UpdatePermission.class);
    }


    static @Nullable Integer validateAssignedTo(Container c, Integer candidate)
    {
        if (null != candidate)
        {
            User user = UserManager.getUser(candidate);

            if (null != user && canAssignTo(c, user))
                return candidate;
        }

        return null;
    }


    public static int getUserEmailPreferences(Container c, int userId)
    {
        Integer[] emailPreference;

        //if the user is inactive, don't send email
        User user = UserManager.getUser(userId);
        if(null != user && !user.isActive())
            return 0;

        emailPreference = new SqlSelector(
                _issuesSchema.getSchema(),
                "SELECT EmailOption FROM " + _issuesSchema.getTableInfoEmailPrefs() + " WHERE Container=? AND UserId=?",
                c, userId).getArray(Integer.class);

        if (emailPreference.length == 0)
        {
            if (userId == UserManager.getGuestUser().getUserId())
            {
                return 0; 
            }
            return DEFAULT_EMAIL_PREFS;
        }
        return emailPreference[0];
    }

    public static class EntryTypeNames
    {
        public String singularName = "Issue";
        public String pluralName = "Issues";

        public String getIndefiniteSingularArticle()
        {
            if (singularName.length() == 0)
                return "";
            char first = Character.toLowerCase(singularName.charAt(0));
            if (first == 'a' || first == 'e' || first == 'i' || first == 'o' || first == 'u')
                return "an";
            else
                return "a";
        }
    }

    /**
     * @param c
     * @return Container c itself or the container from which admin settings were inherited from
     */
    public static Container getInheritFromOrCurrentContainer(Container c)
    {
        Container inheritFrom = getInheritFromContainer(c);

        //Return the container from which admin settings were inherited from
        if(inheritFrom != null)
            return inheritFrom;
        return c;
    }


    @NotNull
    public static EntryTypeNames getEntryTypeNames(Container container)
    {
        Map<String,String> props = PropertyManager.getProperties(getInheritFromOrCurrentContainer(container), CAT_ENTRY_TYPE_NAMES);
        EntryTypeNames ret = new EntryTypeNames();
        if (props.containsKey(PROP_ENTRY_TYPE_NAME_SINGULAR))
            ret.singularName =props.get(PROP_ENTRY_TYPE_NAME_SINGULAR);
        if (props.containsKey(PROP_ENTRY_TYPE_NAME_PLURAL))
            ret.pluralName = props.get(PROP_ENTRY_TYPE_NAME_PLURAL);
        return ret;
    }

    /**
     *
     * @param container
     * @param inheritingVals
     * @return EntryTypeNames of a container with inherited settings, or of current container.
     */
    public static EntryTypeNames getEntryTypeNames(Container container, boolean inheritingVals)
    {
        Container c;
        if(inheritingVals)
            c = getInheritFromOrCurrentContainer(container);
        else
            c = container;

        Map<String,String> props = PropertyManager.getProperties(c, CAT_ENTRY_TYPE_NAMES);
        EntryTypeNames ret = new EntryTypeNames();
        if (props.containsKey(PROP_ENTRY_TYPE_NAME_SINGULAR))
            ret.singularName = props.get(PROP_ENTRY_TYPE_NAME_SINGULAR);
        if (props.containsKey(PROP_ENTRY_TYPE_NAME_PLURAL))
            ret.pluralName = props.get(PROP_ENTRY_TYPE_NAME_PLURAL);
        return ret;
    }

    public static void saveEntryTypeNames(Container container, EntryTypeNames names)
    {
            PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(container, CAT_ENTRY_TYPE_NAMES, true);
            props.put(PROP_ENTRY_TYPE_NAME_SINGULAR, names.singularName);
            props.put(PROP_ENTRY_TYPE_NAME_PLURAL, names.pluralName);
            props.save();
    }


    public static @Nullable Group getAssignedToGroup(Container c)
    {
        Map<String, String> props = PropertyManager.getProperties(c, CAT_ASSIGNED_TO_LIST);

        String groupId = props.get(PROP_ASSIGNED_TO_GROUP);

        if (null == groupId)
            return null;

        return SecurityManager.getGroup(Integer.valueOf(groupId));
    }

    public static void saveAssignedToGroup(Container c, @Nullable Group group)
    {
            PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(c, CAT_ASSIGNED_TO_LIST, true);
            props.put(PROP_ASSIGNED_TO_GROUP, null != group ? String.valueOf(group.getUserId()) : "0");
            props.save();
            uncache();  // uncache the assigned to list
    }

    public static @Nullable User getDefaultAssignedToUser(Container c)
    {
        Map<String, String> props = PropertyManager.getProperties(c, CAT_DEFAULT_ASSIGNED_TO_LIST);
        String userId = props.get(PROP_DEFAULT_ASSIGNED_TO_USER);
        if (null == userId)
            return null;
        User user = UserManager.getUser(Integer.parseInt(userId));
        if (user == null)
            return null;
        if (!canAssignTo(c, user))
            return null;
        return user;
    }

    public static void saveDefaultAssignedToUser(Container c, @Nullable User user)
    {
        PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(c, CAT_DEFAULT_ASSIGNED_TO_LIST, true);
        props.put(PROP_DEFAULT_ASSIGNED_TO_USER, null != user ? String.valueOf(user.getUserId()) : null);
        props.save();
    }

    public static List<Container> getMoveDestinationContainers(Container c)
    {
        Map<String, String> props = PropertyManager.getProperties(getInheritFromOrCurrentContainer(c), CAT_DEFAULT_MOVE_TO_LIST);
        String propsValue = props.get(PROP_DEFAULT_MOVE_TO_CONTAINER);
        List<Container> containers = new LinkedList<>();

        if (propsValue != null)
            for (String containerId : StringUtils.split(propsValue, ';'))
                containers.add( ContainerManager.getForId(containerId));

        return containers;
    }

    public static void saveMoveDestinationContainers(Container c, @Nullable List<Container> containers)
    {
            String propsValue = null;
            if (containers != null && containers.size() != 0)
            {
                StringBuilder sb = new StringBuilder();
                for (Container container : containers)
                    sb.append(String.format(";%s", container.getId()));
                propsValue = sb.toString().substring(1);
            }

            PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(c, CAT_DEFAULT_MOVE_TO_LIST, true);
            props.put(PROP_DEFAULT_MOVE_TO_CONTAINER, propsValue);
            props.save();
    }

    /**
     * @param current
     * @return Container from which current's admin settings are inherited from
     */
    public static Container getInheritFromContainer(Container current)
    {
        Map<String, String> props = PropertyManager.getProperties(current, CAT_DEFAULT_INHERIT_FROM_CONTAINER);
        String propsValue = props.get(PROP_DEFAULT_INHERIT_FROM_CONTAINER);

        Container inheritFromContainer = null;

        if(propsValue != null)
        {
            inheritFromContainer = ContainerManager.getForId(propsValue);
        }

        return inheritFromContainer;
    }

    /**
     * Sets the property of 'current' container with id of a inheritFrom container.
     * 'current' container's settings will "point" to 'inheritFrom' container's
     * admin settings.
     * @param current
     * @param inheritFrom
     */
    public static void saveInheritFromContainer(Container current, @Nullable Container inheritFrom)
    {
        String propsValue = null;

        if(inheritFrom != null)
        {
            propsValue = inheritFrom.getId();
        }

        PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(current, CAT_DEFAULT_INHERIT_FROM_CONTAINER, true);
        props.put(PROP_DEFAULT_INHERIT_FROM_CONTAINER, propsValue);
        props.save();
    }

    public static void saveRelatedIssuesList(Container c, @Nullable String relatedIssuesList)
    {

            String propsValue = null;
            if (relatedIssuesList != null)
            {
                propsValue = relatedIssuesList;
            }

            PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(c, CAT_DEFAULT_RELATED_ISSUES_LIST, true);
            props.put(PROP_DEFAULT_RELATED_ISSUES_LIST, propsValue);
            props.save();
    }

    public static @Nullable Container getRelatedIssuesList(Container c)
    {
        Map<String, String> props = PropertyManager.getProperties(getInheritFromOrCurrentContainer(c), CAT_DEFAULT_RELATED_ISSUES_LIST);
        String containerStr = props.get(PROP_DEFAULT_RELATED_ISSUES_LIST);
        Container container = containerStr == null ? null : ContainerManager.getForPath(containerStr);

        return container;
    }

    public static Sort.SortDirection getCommentSortDirection(Container c)
    {
        Map<String, String> props = PropertyManager.getProperties(getInheritFromOrCurrentContainer(c), CAT_COMMENT_SORT);
        String direction = props.get(CAT_COMMENT_SORT);
        if (direction != null)
        {
            try
            {
                return Sort.SortDirection.valueOf(direction);
            }
            catch (IllegalArgumentException e) {}
        }
        return Sort.SortDirection.ASC; 
    }

    public static void saveCommentSortDirection(Container c, @NotNull Sort.SortDirection direction)
    {
            PropertyManager.PropertyMap props = PropertyManager.getWritableProperties(c, CAT_COMMENT_SORT, true);
            props.put(CAT_COMMENT_SORT, direction.toString());
            props.save();
            uncache();  // uncache the assigned to list
    }


    public static void setUserEmailPreferences(Container c, int userId, int emailPrefs, int currentUser)
    {
        int ret = new SqlExecutor(_issuesSchema.getSchema()).execute(
                "UPDATE " + _issuesSchema.getTableInfoEmailPrefs() + " SET EmailOption=? WHERE Container=? AND UserId=?",
                emailPrefs, c, userId);


        if (ret == 0)
        {
            // record doesn't exist yet...
            new SqlExecutor(_issuesSchema.getSchema()).execute(
                    "INSERT INTO " + _issuesSchema.getTableInfoEmailPrefs() + " (Container, UserId, EmailOption ) VALUES (?, ?, ?)",
                    c, userId, emailPrefs);
        }
    }

    public static List<ValidEmail> getSubscribedUserEmails(Container c)
    {
        List<ValidEmail> emails = new ArrayList<>();

        SqlSelector ss = new SqlSelector(_issuesSchema.getSchema().getScope(), new SQLFragment("SELECT UserId FROM " + _issuesSchema.getTableInfoEmailPrefs() + " WHERE Container = ? and (EmailOption & ?) = ?", c.getId(), NOTIFY_SUBSCRIBE, NOTIFY_SUBSCRIBE));
        Integer[] userIds = ss.getArray(Integer.class);

        for (Integer userId : userIds)
        {
            String email = UserManager.getEmailForId(userId);
            if (email != null)
            {
                try
                {
                    ValidEmail ve = new ValidEmail(email);
                    emails.add(ve);
                }
                catch (ValidEmail.InvalidEmailException e)
                {
                    //ignore
                }
            }
        }

        return emails;
    }

    public static void deleteUserEmailPreferences(User user)
    {
        Table.delete(_issuesSchema.getTableInfoEmailPrefs(), new SimpleFilter(FieldKey.fromParts("UserId"), user.getUserId()));
    }

    public static long getIssueCount(Container c)
    {
        return new TableSelector(_issuesSchema.getTableInfoIssues(), SimpleFilter.createContainerFilter(c), null).getRowCount();
    }

    public static void uncache()
    {
        ASSIGNED_TO_CACHE.clear(); //Lazy uncache: uncache ALL the containers for updated values in case any folder is inheriting its Admin settings.
    }

    public static void purgeContainer(Container c)
    {
        try (DbScope.Transaction transaction = _issuesSchema.getSchema().getScope().ensureTransaction())
        {
            String deleteStmt = "DELETE FROM %s WHERE IssueId IN (SELECT IssueId FROM %s WHERE Container = ?)";

            String deleteComments = String.format(deleteStmt, _issuesSchema.getTableInfoComments(), _issuesSchema.getTableInfoIssues());
            new SqlExecutor(_issuesSchema.getSchema()).execute(deleteComments, c.getId());

            String deleteRelatedIssues = String.format(deleteStmt, _issuesSchema.getTableInfoRelatedIssues(), _issuesSchema.getTableInfoIssues());
            new SqlExecutor(_issuesSchema.getSchema()).execute(deleteRelatedIssues, c.getId());

            ContainerUtil.purgeTable(_issuesSchema.getTableInfoIssues(), c, null);
            ContainerUtil.purgeTable(_issuesSchema.getTableInfoIssueKeywords(), c, null);
            ContainerUtil.purgeTable(_issuesSchema.getTableInfoEmailPrefs(), c, null);
            ContainerUtil.purgeTable(_issuesSchema.getTableInfoCustomColumns(), c, null);

            transaction.commit();
        }
    }


    public static String purge() throws SQLException
    {
        String message = "";

        try (DbScope.Transaction transaction = _issuesSchema.getSchema().getScope().ensureTransaction())
        {
            String subQuery = String.format("SELECT IssueId FROM %s WHERE Container NOT IN (SELECT EntityId FROM core.Containers)", _issuesSchema.getTableInfoIssues());

            String deleteComments = String.format("DELETE FROM %s WHERE IssueId IN (%s)", _issuesSchema.getTableInfoComments(), subQuery);
            int commentsDeleted = new SqlExecutor(_issuesSchema.getSchema()).execute(deleteComments);

            String deleteOrphanedComments =
                    "DELETE FROM " + _issuesSchema.getTableInfoComments() + " WHERE IssueId NOT IN (SELECT IssueId FROM " + _issuesSchema.getTableInfoIssues() + ")";
            commentsDeleted += new SqlExecutor(_issuesSchema.getSchema()).execute(deleteOrphanedComments);

            // NOTE: this is ugly...
            String deleteRelatedIssues = String.format("DELETE FROM %s WHERE IssueId IN (%s) OR RelatedIssueId IN (%s)", _issuesSchema.getTableInfoRelatedIssues(), subQuery, subQuery);
            int relatedIssuesDeleted = new SqlExecutor(_issuesSchema.getSchema()).execute(deleteRelatedIssues);

            int issuesDeleted = ContainerUtil.purgeTable(_issuesSchema.getTableInfoIssues(), null);
            ContainerUtil.purgeTable(_issuesSchema.getTableInfoIssueKeywords(), null);
            transaction.commit();

            message = String.format("deleted %d issues<br>\ndeleted %d comments<br>\ndeleted %d relatedIssues", issuesDeleted, commentsDeleted, relatedIssuesDeleted);
        }

        return message;
    }

    /**
     *
     * @param container
     * @return combined Required fields of "current" and "inherited from" container if admin settings are inherited
     */
    public static String getRequiredIssueFields(Container container)
    {
        Map<String, String> map = PropertyManager.getProperties(getInheritFromOrCurrentContainer(container), ISSUES_PREF_MAP);
        String requiredFields = map.get(ISSUES_REQUIRED_FIELDS);

        if(getInheritFromContainer(container) != null)
        {
            return getMyRequiredIssueFields(container) + ";" + requiredFields;
        }
        return null == requiredFields ? IssuesController.DEFAULT_REQUIRED_FIELDS : requiredFields.toLowerCase();
    }

    /**
     *
     * @param container
     * @return Required fields of the current container
     */
    public static String getMyRequiredIssueFields(Container container)
    {
        Map<String, String> mapCurrent = PropertyManager.getProperties(container, ISSUES_PREF_MAP);
        String requiredFieldsCurrent = mapCurrent.get(ISSUES_REQUIRED_FIELDS);
        return (null == requiredFieldsCurrent) ? IssuesController.DEFAULT_REQUIRED_FIELDS : requiredFieldsCurrent.toLowerCase();
    }

    /**
     *
     * @param container
     * @return Required fields of the container from which current container's admin settings were inherited from
     */
    public static String getInheritedRequiredIssueFields(Container container)
    {
        Map<String, String> map = PropertyManager.getProperties(getInheritFromOrCurrentContainer(container), ISSUES_PREF_MAP);
        String requiredFields = map.get(ISSUES_REQUIRED_FIELDS);
        return null == requiredFields ? IssuesController.DEFAULT_REQUIRED_FIELDS : requiredFields.toLowerCase();
    }


    public static void setRequiredIssueFields(Container container, String requiredFields)
    {
        PropertyManager.PropertyMap map = PropertyManager.getWritableProperties(container, ISSUES_PREF_MAP, true);

        if (!StringUtils.isEmpty(requiredFields))
            requiredFields = requiredFields.toLowerCase();
        map.put(ISSUES_REQUIRED_FIELDS, requiredFields);
        map.save();
    }

    public static void setRequiredIssueFields(Container container, String[] requiredFields)
    {
            final StringBuilder sb = new StringBuilder();
            if (requiredFields.length > 0)
            {
                String sep = "";
                for (String field : requiredFields)
                {
                    sb.append(sep);
                    sb.append(field);
                    sep = ";";
                }
            }
            setRequiredIssueFields(container, sb.toString());
    }

    public static void setLastIndexed(String containerId, int issueId, long ms)
    {
        new SqlExecutor(_issuesSchema.getSchema()).execute(
                "UPDATE issues.issues SET lastIndexed=? WHERE container=? AND issueId=?",
                new Timestamp(ms), containerId, issueId);
    }
    

    public static void indexIssues(IndexTask task, @NotNull Container c, Date modifiedSince)
    {
        SearchService ss = ServiceRegistry.get().getService(SearchService.class);
        if (null == ss)
            return;
        
        SimpleFilter f = SimpleFilter.createContainerFilter(c);
        SearchService.LastIndexedClause incremental = new SearchService.LastIndexedClause(_issuesSchema.getTableInfoIssues(), modifiedSince, null);
        if (!incremental.toSQLFragment(null,null).isEmpty())
            f.addClause(incremental);
        if (f.getClauses().isEmpty())
            f = null;

        // Index issues in batches of 100
        new TableSelector(_issuesSchema.getTableInfoIssues(), PageFlowUtil.set("issueid"), f, null)
                .forEachBatch(batch -> task.addRunnable(new IndexGroup(task, batch), SearchService.PRIORITY.group), Integer.class, 100);
    }

    private static class IndexGroup implements Runnable
    {
        private final List<Integer> _ids;
        private final IndexTask _task;
        
        IndexGroup(IndexTask task, List<Integer> ids)
        {
            _ids = ids;
            _task = task;
        }

        public void run()
        {
            indexIssues(_task, _ids);
        }
    }


    /* CONSIDER: some sort of generator interface instead */
    public static void indexIssues(IndexTask task, Collection<Integer> ids)
    {
        if (ids.isEmpty())
            return;

        SQLFragment f = new SQLFragment();
        f.append("SELECT I.issueId, I.container, I.entityid, I.title, I.status, AssignedTo$.searchTerms as assignedto, I.type, I.area, ")
            .append("I.priority, I.milestone, I.buildfound, ModifiedBy$.searchTerms as modifiedby, ")
            .append("I.modified, CreatedBy$.searchTerms as createdby, I.created, I.tag, ResolvedBy$.searchTerms as resolvedby, ")
            .append("I.resolved, I.resolution, I.duplicate, ClosedBy$.searchTerms as closedby, I.closed, ")
            .append("I.int1, I.int2, I.string1, I.string2, ")
            .append("C.comment\n");
        f.append("FROM issues.issues I \n")
            .append("LEFT OUTER JOIN issues.comments C ON I.issueid = C.issueid\n")
            .append("LEFT OUTER JOIN core.usersearchterms AS AssignedTo$ ON I.assignedto = AssignedTo$.userid\n")
            .append("LEFT OUTER JOIN core.usersearchterms AS ClosedBy$  ON I.createdby = ClosedBy$.userid\n")
            .append("LEFT OUTER JOIN core.usersearchterms AS CreatedBy$  ON I.createdby = CreatedBy$.userid\n")
            .append("LEFT OUTER JOIN core.usersearchterms AS ModifiedBy$ ON I.modifiedby = ModifiedBy$.userid\n")
            .append("LEFT OUTER JOIN core.usersearchterms AS ResolvedBy$ ON I.modifiedby = ResolvedBy$.userid\n");
        f.append("WHERE I.issueid IN ");

        String comma = "(";
        for (Integer id : ids)
        {
            f.append(comma).append(id);
            comma = ",";
        }
        f.append(")\n");
        f.append("ORDER BY I.issueid, C.created");

        try (ResultSet rs = new SqlSelector(_issuesSchema.getSchema(), f).getResultSet(false))
        {
            ResultSetRowMapFactory factory = ResultSetRowMapFactory.create(rs);
            int currentIssueId = -1;

            Map<String, Object> m = null;
            ArrayList<Issue.Comment> comments = new ArrayList<>();

            while (rs.next())
            {
                int id = rs.getInt(1);
                if (id != currentIssueId)
                {
                    queueIssue(task, currentIssueId, m, comments);
                    comments = new ArrayList<>();
                    m = factory.getRowMap(rs);
                    currentIssueId = id;
                }
                comments.add(new Issue.Comment(rs.getString("comment")));
            }
            queueIssue(task, currentIssueId, m, comments);
        }
        catch (SQLException x)
        {
            throw new RuntimeSQLException(x);
        }
    }


    static void indexIssue(@Nullable IndexTask task, Issue issue)
    {
        if (task == null)
        {
            SearchService ss = ServiceRegistry.get().getService(SearchService.class);
            if (null == ss)
                return;
            task = ss.defaultTask();
        }

        // UNDONE: broken ??
        // task.addResource(new IssueResource(issue), SearchService.PRIORITY.item);

        // try requery instead
        indexIssues(task, Collections.singleton(issue.getIssueId()));
    }


    static void queueIssue(IndexTask task, int id, Map<String,Object> m, ArrayList<Issue.Comment> comments)
    {
        if (null == task || null == m)
            return;
        String title = String.valueOf(m.get("title"));
        m.put(SearchService.PROPERTY.title.toString(), id + " : " + title);
        m.put("comment", null);
        m.put("_row", null);
        task.addResource(new IssueResource(id, m, comments), SearchService.PRIORITY.item);
    }


    public static SearchService.ResourceResolver getSearchResolver()
    {
        return new SearchService.ResourceResolver()
        {
            public WebdavResource resolve(@NotNull String resourceIdentifier)
            {
                return IssueManager.resolve(resourceIdentifier);
            }

            @Override
            public HttpView getCustomSearchResult(User user, @NotNull String resourceIdentifier)
            {
                int issueId;
                try
                {
                    issueId = Integer.parseInt(resourceIdentifier);
                }
                catch (NumberFormatException x)
                {
                    return null;
                }

                final Issue issue = getIssue(null, issueId);
                if (null == issue)
                    return null;
                Container c = issue.lookupContainer();
                if (null == c || !c.hasPermission(user, ReadPermission.class))
                    return null;

                return new IssueSummaryView(issue);
            }
        };
    }


    public static class IssueSummaryView extends JspView
    {
        IssueSummaryView(Issue issue)
        {
            super("/org/labkey/issue/view/searchSummary.jsp", issue);
        }
    }


    public static WebdavResource resolve(String id)
    {
        int issueId;
        try
        {
            issueId = Integer.parseInt(id);
        }
        catch (NumberFormatException x)
        {
            return null;
        }

        final Issue issue = getIssue(null, issueId);
        if (null == issue)
            return null;

        return new IssueResource(issue);
    }


    static final ObjectFactory _issueFactory = ObjectFactory.Registry.getFactory(Issue.class);

    private static class IssueResource extends AbstractDocumentResource
    {
        Collection<Issue.Comment> _comments;
        final int _issueId;

        IssueResource(Issue issue)
        {
            super(new Path("issue:" + String.valueOf(issue.getIssueId())));
            _issueId = issue.issueId;
            Map<String,Object> m = _issueFactory.toMap(issue, null);
            // UNDONE: custom field names
            // UNDONE: user names
            m.remove("comments");
            _containerId = issue.getContainerId();
            _properties = m;
            _comments = issue.getComments();
            _properties.put(categories.toString(), searchCategory.getName());
        }


        IssueResource(int issueId, Map<String,Object> m, List<Issue.Comment> comments)
        {
            super(new Path("issue:"+String.valueOf(issueId)));
            _issueId = issueId;
            _containerId = (String)m.get("container");
            _properties = m;
            _comments = comments;
            _properties.put(categories.toString(), searchCategory.getName());
        }


        @Override
        public void setLastIndexed(long ms, long modified)
        {
            IssueManager.setLastIndexed(_containerId, _issueId, ms);
        }

        public String getDocumentId()
        {
            return "issue:"+String.valueOf(_properties.get("issueid"));
        }


        public boolean exists()
        {
            return true;
        }

        @Override
        public String getExecuteHref(ViewContext context)
        {
            ActionURL url = new ActionURL(IssuesController.DetailsAction.class, null).addParameter("issueId", String.valueOf(_properties.get("issueid")));
            url.setExtraPath(_containerId);
            return url.getLocalURIString();
        }

        @Override
        public String getContentType()
        {
            return "text/html";
        }


        public FileStream getFileStream(User user) throws IOException
        {
            String title = String.valueOf(_properties.get("title"));

            try (ByteArrayOutputStream bos = new ByteArrayOutputStream())
            {
                try (Writer out = new OutputStreamWriter(bos))
                {

                    out.write("<html><head><title>");
                    out.write(PageFlowUtil.filter(title));
                    out.write("</title></head><body>");
                    out.write(PageFlowUtil.filter(title));
                    out.write("\n");
                    for (Issue.Comment c : _comments)
                        if (null != c.getComment())
                            out.write(c.getComment());
                }
                return new FileStream.ByteArrayFileStream(bos.toByteArray());
            }
        }
        
        public InputStream getInputStream(User user) throws IOException
        {
            return getFileStream(user).openInputStream();
        }

        public long copyFrom(User user, FileStream in) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public long getContentLength() throws IOException
        {
            throw new UnsupportedOperationException();
        }
    }


    public static class TestCase extends Assert
    {
        @Test
        public void testIssues() throws IOException, SQLException, ServletException
        {
            TestContext context = TestContext.get();

            User user = context.getUser();
            assertTrue("login before running this test", null != user);
            assertFalse("login before running this test", user.isGuest());

            Container c = JunitUtil.getTestContainer();

            int issueId;

            //
            // INSERT
            //
            {
                Issue issue = new Issue();
                issue.open(c, user);
                issue.setAssignedTo(user.getUserId());
                issue.setTitle("This is a junit test bug");
                issue.setTag("junit");
                issue.addComment(user, "new issue");
                issue.setPriority(3);

                IssueManager.saveIssue(user, c, issue);
                issueId = issue.getIssueId();
            }

            // verify
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                assertEquals("This is a junit test bug", issue.getTitle());
                assertEquals(user.getUserId(), issue.getCreatedBy());
                assertTrue(issue.getCreated().getTime() != 0);
                assertTrue(issue.getModified().getTime() != 0);
                assertEquals(user.getUserId(), issue.getAssignedTo().intValue());
                assertEquals(Issue.statusOPEN, issue.getStatus());
                assertEquals(1, issue.getComments().size());
				String comment = (issue.getComments().iterator().next()).getComment();
                assertTrue("new issue".equals(comment));
            }

            //
            // ADD COMMENT
            //
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                issue.addComment(user, "what was I thinking");
                IssueManager.saveIssue(user, c, issue);
            }

            // verify
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                assertEquals(2, issue.getComments().size());
                Iterator it = issue.getComments().iterator();
                assertEquals("new issue", ((Issue.Comment) it.next()).getComment());
                assertEquals("what was I thinking", ((Issue.Comment) it.next()).getComment());
            }

            //
            // ADD INVALID COMMENT
            //
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                issue.addComment(user, "invalid character <\u0010>");
                try
                {
                    IssueManager.saveIssue(user, c, issue);
                    fail("Expected to throw exception for an invalid character.");
                }
                catch (ConversionException ex)
                {
                    // expected exception.
                    assertEquals("comment has invalid characters", ex.getMessage());
                }
            }

            //
            // RESOLVE
            //
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                assertNotNull("issue not found", issue);
                issue.resolve(user);

                Issue copy = (Issue) JunitUtil.copyObject(issue);
                copy.setResolution("fixed");
                copy.addComment(user, "fixed it");
                IssueManager.saveIssue(user, c, copy);
            }

            // verify
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                assertEquals(Issue.statusRESOLVED, issue.getStatus());
                assertEquals(3, issue.getComments().size());
            }

            //
            // CLOSE
            //
            {
                Issue issue = getIssue(c, issueId);
                assertNotNull("issue not found", issue);
                issue.close(user);

                Issue copy = (Issue) JunitUtil.copyObject(issue);
                copy.addComment(user, "closed");
                IssueManager.saveIssue(user, c, copy);
            }

            // verify
            {
                Issue issue = IssueManager.getIssue(c, issueId);
                assertEquals(Issue.statusCLOSED, issue.getStatus());
                assertEquals(4, issue.getComments().size());
            }
        }

        @Test
        public void testEmailHiding() throws IOException, SQLException, ServletException
        {
            Container fakeRoot = ContainerManager.createFakeContainer(null, null);

            User user = UserManager.getGuestUser();
            boolean showEmailAddresses = SecurityManager.canSeeEmailAddresses(fakeRoot, user);
            assertFalse("readers should not see emails", showEmailAddresses);
            List<User> possibleUsers = SecurityManager.getUsersWithPermissions(fakeRoot, Collections.<Class<? extends Permission>>singleton(ReadPermission.class));

            for (AjaxCompletion completion : UserManager.getAjaxCompletions(possibleUsers, user, fakeRoot))
            {
                User u = UserManager.getUserByDisplayName(completion.getInsertionText());
                if (u != null)
                    assertFalse("readers should not see emails", completion.getDisplayText().toLowerCase().contains(u.getEmail().toLowerCase()));
            }

            // this should be an admin...
            user = TestContext.get().getUser();
            showEmailAddresses = SecurityManager.canSeeEmailAddresses(fakeRoot, user);
            assertTrue("admins should see emails", showEmailAddresses);

            for (AjaxCompletion completion : UserManager.getAjaxCompletions(possibleUsers, user, fakeRoot))
            {
                User u = UserManager.getUserByDisplayName(completion.getInsertionText());
                if (u != null)
                    assertTrue("admins should see emails", completion.getDisplayText().toLowerCase().contains(u.getEmail().toLowerCase()));
            }
        }

        @After
        public void tearDown()
        {
            Container c = JunitUtil.getTestContainer();
            SqlExecutor executor = new SqlExecutor(_issuesSchema.getSchema());

            SQLFragment deleteComments = new SQLFragment("DELETE FROM " + _issuesSchema.getTableInfoComments() +
                " WHERE IssueId IN (SELECT IssueId FROM " + _issuesSchema.getTableInfoIssues() + " WHERE Container = ?)", c.getId());
            executor.execute(deleteComments);
            SQLFragment deleteIssues = new SQLFragment("DELETE FROM " + _issuesSchema.getTableInfoIssues() + " WHERE Container = ?", c.getId());
            executor.execute(deleteIssues);
        }
    }
}
