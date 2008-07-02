/*
 * Copyright (c) 2008 LabKey Corporation
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
package org.labkey.core.admin;

import org.labkey.api.data.*;
import org.labkey.api.util.PageFlowUtil;

import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * User: adam
 * Date: Jun 29, 2008
 * Time: 5:32:14 AM
 */
public abstract class ViewHandler
{
    protected FileSqlScriptProvider _provider;
    protected String _schemaName;
    private enum ViewType {DROP, CREATE}
    private List<String> _createNames = Collections.emptyList();
    private List<String> _dropNames = Collections.emptyList();

    protected Pattern _viewPattern;

    private ViewHandler(FileSqlScriptProvider provider, String schemaName)
    {
        _provider = provider;
        _schemaName = schemaName;

        boolean isPostgreSQL = DbSchema.get(_schemaName).getSqlDialect().isPostgreSQL();

        String initialCommentRegEx = "(?-m:^--.*?\\s*)?";    // This isn't working...
        String viewNameRegEx = "((\\w+)\\.)?(\\w+)";
        String dropRegEx;
        String createRegEx;
        String endRegEx;

        if (isPostgreSQL)
        {
            dropRegEx = "((DROP VIEW " + viewNameRegEx + ")|(SELECT core.fn_dropifexists\\s*\\(\\s*'(\\w+)',\\s*'(\\w+)',\\s*'VIEW',\\s*NULL\\s*\\)))";      // exec core.fn_dropifexists 'materialsource', 'cabig','VIEW', NULL
            createRegEx = "(CREATE (?:OR REPLACE )*VIEW " + viewNameRegEx + " AS.+?)";
            endRegEx = ";";
        }
        else
        {
            dropRegEx = "((DROP VIEW " + viewNameRegEx + ")|(EXEC core.fn_dropifexists\\s*'(\\w+)',\\s*'(\\w+)',\\s*'VIEW',\\s*NULL))";      // exec core.fn_dropifexists 'materialsource', 'cabig','VIEW', NULL
            createRegEx = "(CREATE VIEW " + viewNameRegEx + " AS.+?)";
            endRegEx = "GO$";
        }

        String combinedRegEx = (initialCommentRegEx + "(?:" + dropRegEx + "|" + createRegEx + ")\\s*" + endRegEx + "\\s*").replaceAll(" ", "\\\\s+");
        _viewPattern = Pattern.compile(combinedRegEx, Pattern.CASE_INSENSITIVE + Pattern.DOTALL + Pattern.MULTILINE);
    }

    public List<String> getCreateNames()
    {
        return _createNames;
    }

    public List<String> getDropNames()
    {
        return _dropNames;
    }

    protected abstract List<SqlScriptRunner.SqlScript> getScripts() throws SqlScriptRunner.SqlScriptException;
    // Called only if one or more VIEW statements exist in this script
    protected abstract void handleScript(SqlScriptRunner.SqlScript script, Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out);
    // Called only if one or more VIEW statements exist in this schema
    protected abstract void handleSchema(Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out);

    public void handle(PrintWriter out) throws SqlScriptRunner.SqlScriptException
    {
        // These maps are ordered by most recent access, which helps us figure out the dependency order
        Map<String, String> createStatements = new LinkedHashMap<String, String>(10, 0.75f, true);
        Map<String, String> dropStatements = new LinkedHashMap<String, String>(10, 0.75f, true);

        for (SqlScriptRunner.SqlScript script : getScripts())
        {
            Set<String> temporaryViews = new HashSet<String>();
            Matcher m = _viewPattern.matcher(script.getContents());

            while (m.find())
            {
                String schemaName;
                String viewName;
                ViewType type;

                // CREATE VIEW
                if (null != m.group(9))
                {
                    schemaName = m.group(11);
                    viewName = m.group(12);
                    type = ViewType.CREATE;
                }
                else
                {
                    // EXEC/SELECT core.fn_dropifexists
                    if (null != m.group(6))
                    {
                        schemaName = m.group(8);
                        viewName = m.group(7);
                        type = ViewType.DROP;
                    }
                    // DROP VIEW
                    else
                    {
                        assert null != m.group(2);
                        schemaName = m.group(4);
                        viewName = m.group(5);
                        type = ViewType.DROP;
                    }
                }

                String key = getKey(_schemaName, schemaName, viewName);

                if (viewName.startsWith("_"))
                {
                    if (type == ViewType.CREATE)
                    {
                        assert temporaryViews.add(key);
                    }
                    else
                    {
                        assert temporaryViews.remove(key);
                    }
                }
                else
                {
                    if (ViewType.CREATE == type)
                    {
                        createStatements.put(key, m.group(0));
                    }
                    else
                    {
                        dropStatements.put(key, (null == schemaName ? _schemaName : schemaName) + "." + viewName);
                        createStatements.remove(key);
                    }
                }
            }

            if (!temporaryViews.isEmpty())
            {
                out.println("========== TEMPORARY VIEWS ERROR ==========");
                out.println(temporaryViews.toString());
            }

            if (!createStatements.isEmpty() || !dropStatements.isEmpty())
                handleScript(script, createStatements, dropStatements, out);
        }

        if (!createStatements.isEmpty() || !dropStatements.isEmpty())
        {
            _createNames = new ArrayList<String>(createStatements.keySet());
            _dropNames = new ArrayList<String>(dropStatements.keySet());
            handleSchema(createStatements, dropStatements, out);
        }
    }


    private String getKey(String defaultSchemaName, String schemaName, String viewName)
    {
        return ((null != schemaName ? schemaName : defaultSchemaName) + "." + viewName).toLowerCase();
    }


    // Clears CREATE and DROP view statements from all current scripts
    public static class ViewClearer extends ViewHandler
    {
        ViewClearer(FileSqlScriptProvider provider, String schemaName)
        {
            super(provider, schemaName);
        }

        // Clear VIEW statements from all current scripts
        protected List<SqlScriptRunner.SqlScript> getScripts() throws SqlScriptRunner.SqlScriptException
        {
            return _provider.getScripts(_schemaName);
        }

        protected void handleScript(SqlScriptRunner.SqlScript script, Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out)
        {
/*          TODO: Enable this!
            Matcher m = _viewPattern.matcher(script.getContents());
            String strippedScript = m.replaceAll("");
            out.println("========== " + script.getDescription() + " ==========");
            out.println(PageFlowUtil.filter(strippedScript));
            out.println();
*/
        }

        protected void handleSchema(Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out)
        {
        }
    }

    // Creates DROP VIEW (for all views that have ever been created) and CREATE VIEW (all current VIEWs) scripts
    public static class ViewExtractor extends ViewHandler
    {
        public ViewExtractor(FileSqlScriptProvider provider, String schemaName)
        {
            super(provider, schemaName);
        }

        // Use the recommended scripts from 0.00 to highest version in each schema
        protected List<SqlScriptRunner.SqlScript> getScripts() throws SqlScriptRunner.SqlScriptException
        {
            return SqlScriptRunner.getRecommendedScripts(_provider.getScripts(_schemaName), 0.0, Double.MAX_VALUE);
        }

        protected void handleScript(SqlScriptRunner.SqlScript script, Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out)
        {
        }

        // Careful: createStatements and dropStatements are special LRU maps.  Their order will change on every access.
        protected void handleSchema(Map<String, String> createStatements, Map<String, String> dropStatements, PrintWriter out)
        {
            // Get the CREATE VIEW names, reverse their order, and create a DROP statement for each
            List<String> dropNames = new ArrayList<String>();
            List<String> keys = new ArrayList<String>(createStatements.size());
            keys.addAll(createStatements.keySet());
            Collections.reverse(keys);

            for (String key : keys)
            {
                String createStatement = createStatements.get(key);    // NOTE: This access will change the map order.  Don't iterate createStatements past this point.
                Matcher m = _viewPattern.matcher(createStatement);
                m.find();
                String schemaName = (null != m.group(11) ? m.group(11) : _schemaName);
                String viewName = m.group(12);
                dropNames.add(schemaName + "." + viewName);
                dropStatements.remove(key);
            }

            // Add a DROP statement for everything left in dropStatements -- these are obsolete views, but we still need to drop them.
            if (!dropStatements.isEmpty())
            {
                out.println("-- DROP obsolete views.  Do not remove these statements; they are needed when upgrading from older versions.");
                outputDropViews(out, dropStatements.values());
                out.println();
            }
            out.println("-- DROP current views.");
            outputDropViews(out, dropNames);

            // Reverse the keys back to order of CREATE VIEW statements in the scripts.
            Collections.reverse(keys);

            // Iterate keys, since the map order has probably changed.
            for (String key : keys)
            {
                out.println(PageFlowUtil.filter(createStatements.get(key)));
            }
        }

        private void outputDropViews(PrintWriter out, Collection<String> viewNames)
        {
            for (String viewName : viewNames)
            {
                String[] parts = viewName.split("\\.");
                DbSchema schema = DbSchema.get(parts[0]);
                String sql = schema.getSqlDialect().execute(CoreSchema.getInstance().getSchema(), "fn_dropifexists", "'" + parts[1] + "', '" + parts[0] + "', 'VIEW', NULL") + (schema.getSqlDialect().isPostgreSQL() ? ";" : "");
                out.println(PageFlowUtil.filter(sql));
            }

            if (DbSchema.get(_schemaName).getSqlDialect().isSqlServer())
                out.println("GO");
        }
    }
}
