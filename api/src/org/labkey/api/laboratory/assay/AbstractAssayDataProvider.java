/*
 * Copyright (c) 2012-2013 LabKey Corporation
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
package org.labkey.api.laboratory.assay;

import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import org.labkey.api.data.Container;
import org.labkey.api.data.PropertyManager;
import org.labkey.api.data.TableInfo;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.exp.api.ExpRun;
import org.labkey.api.laboratory.AbstractDataProvider;
import org.labkey.api.laboratory.LaboratoryService;
import org.labkey.api.laboratory.SimpleQueryNavItem;
import org.labkey.api.laboratory.SingleNavItem;
import org.labkey.api.laboratory.TabbedReportItem;
import org.labkey.api.ldk.NavItem;
import org.labkey.api.module.Module;
import org.labkey.api.query.DetailsURL;
import org.labkey.api.query.QueryDefinition;
import org.labkey.api.query.QueryException;
import org.labkey.api.security.User;
import org.labkey.api.study.assay.AssayProtocolSchema;
import org.labkey.api.study.assay.AssayProvider;
import org.labkey.api.study.assay.AssayService;
import org.labkey.api.study.assay.AssayUrls;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.ViewContext;
import org.labkey.api.view.template.ClientDependency;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: bimber
 * Date: 10/1/12
 * Time: 1:52 PM
 */
abstract public class AbstractAssayDataProvider extends AbstractDataProvider implements AssayDataProvider
{
    public static final String PROPERTY_CATEGORY = "laboratory.importMethodDefaults";

    protected String _providerName = null;
    protected Collection<AssayImportMethod> _importMethods = new LinkedHashSet<AssayImportMethod>();
    protected Module _module = null;

    public String getName()
    {
        return _providerName;
    }

    public ActionURL getInstructionsUrl(Container c, User u)
    {
        return null;
    }

    public List<NavItem> getDataNavItems(Container c, User u)
    {
        List<NavItem> items = new ArrayList<NavItem>();
        List<ExpProtocol> protocols = getProtocols(c);
        for (ExpProtocol p : protocols)
        {
            items.add(new AssayNavItem(this, p));
        }
        return items;
    }

    public List<ExpProtocol> getProtocols(Container c)
    {
        List<ExpProtocol> list = new ArrayList<ExpProtocol>();
        List<ExpProtocol> protocols = AssayService.get().getAssayProtocols(c);
        for (ExpProtocol p : protocols)
        {
            AssayProvider provider = AssayService.get().getProvider(p);
            if (provider == null)
                continue;
            if (provider.equals(getAssayProvider()))
                list.add(p);
        }

        return list;
    }

    public boolean isModuleEnabled(Container c)
    {
        return _module == null ? true : c.getActiveModules().contains(_module);
    }

    public List<NavItem> getSampleNavItems(Container c, User u)
    {
        return Collections.emptyList();
    }

    public List<NavItem> getSettingsItems(Container c, User u)
    {
        return Collections.emptyList();
    }

    public String getProviderName()
    {
        return _providerName;
    }

    public AssayProvider getAssayProvider()
    {
        return AssayService.get().getProvider(_providerName);
    }

    public Collection<AssayImportMethod> getImportMethods()
    {
        return _importMethods;
    }

    public AssayImportMethod getImportMethodByName(String methodName)
    {
        for (AssayImportMethod m : _importMethods)
        {
            if (m.getName().equals(methodName))
                return m;
        }
        return null;
    }

    public String getDefaultImportMethodName(Container c, User u, int protocolId)
    {
        Container targetContainer = c.isWorkbook() ? c.getParent() : c;
        Map<String, String> props = PropertyManager.getProperties(targetContainer, PROPERTY_CATEGORY);
        if (props.containsKey(getDefaultMethodPropertyKey(protocolId)))
            return props.get(getDefaultMethodPropertyKey(protocolId));
        else
            return _importMethods.size() == 0 ?  null : _importMethods.iterator().next().getName();
    }

    private String getDefaultMethodPropertyKey(int protocolId)
    {
        return getKey() + "||" + protocolId;
    }

    public boolean supportsRunTemplates()
    {
        for (AssayImportMethod im : getImportMethods())
        {
            if (im.supportsRunTemplates())
            {
                return true;
            }
        }
        return false;
    }

    public JSONObject getTemplateMetadata(ViewContext ctx)
    {
        JSONObject meta = new JSONObject();
        JSONObject domainMeta = new JSONObject();

        JSONObject runMeta = new JSONObject();
        JSONObject nameField = new JSONObject();
        nameField.put("hidden", true);
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
        nameField.put("value", ctx.getUser().getDisplayName(ctx.getUser()) + "_" + format.format(new Date()));
        runMeta.put("Name", nameField);

        runMeta.put("runDate", new JSONObject().put("hidden", true));
        runMeta.put("comments", new JSONObject().put("hidden", true));
        runMeta.put("performedBy", new JSONObject().put("hidden", true));
        domainMeta.put("Run", runMeta);

        JSONObject resultMeta = getJsonObject(domainMeta, "Results");
        resultMeta.put("sampleId", new JSONObject().put("lookups", false));
        resultMeta.put("subjectId", new JSONObject().put("lookups", false));

        String[] hiddenResultFields = new String[]{"result", "qual_result", "qcstate", "requestid", "Run"};
        for (String field : hiddenResultFields)
        {
            JSONObject json = getJsonObject(resultMeta, field);
            json.put("hidden", true);
            resultMeta.put(field, json);
        }

        domainMeta.put("Results", resultMeta);

        meta.put("domains", domainMeta);

        return meta;
    }

    @Override
    public List<NavItem> getReportItems(Container c, User u)
    {
        List<NavItem> items = new ArrayList<NavItem>();
        for (ExpProtocol p : getProtocols(c))
        {
            AssayNavItem nav = new AssayNavItem(this, p);
            AssayProtocolSchema schema = getAssayProvider().createProtocolSchema(u, c, p, null);
            SimpleQueryNavItem item = new SimpleQueryNavItem(this, schema.getSchemaName(), AssayProtocolSchema.DATA_TABLE_NAME, _providerName, p.getName() + ": Raw Data");
            item.setVisible(nav.isVisible(c, u));
            item.setOwnerKey(nav.getPropertyManagerKey());
            items.add(item);

            //for file-based assays, append any associated queries
            List<QueryDefinition> queries = schema.getFileBasedAssayProviderScopedQueries();
            for (QueryDefinition qd : queries)
            {
                TableInfo query = qd.getTable(new ArrayList<QueryException>(), true);
                SimpleQueryNavItem qItem = new SimpleQueryNavItem(this, schema.getSchemaName(), qd.getName(), _providerName, p.getName() + ": " + query.getTitle());
                qItem.setVisible(nav.isVisible(c, u));
                qItem.setOwnerKey(nav.getPropertyManagerKey());
                items.add(qItem);
            }
        }
        return Collections.unmodifiableList(items);
    }

    @Override
    public List<TabbedReportItem> getTabbedReportItems(Container c, User u)
    {
        List<TabbedReportItem> items = new ArrayList<TabbedReportItem>();
        for (ExpProtocol p : getProtocols(c))
        {
            AssayNavItem nav = new AssayNavItem(this, p);
            AssayProtocolSchema schema = getAssayProvider().createProtocolSchema(u, c, p, null);
            TabbedReportItem item = new TabbedReportItem(this, schema.getSchemaName(), AssayProtocolSchema.DATA_TABLE_NAME, p.getName() + ": Raw Data", _providerName);
            item.setVisible(nav.isVisible(c, u));
            item.setOwnerKey(nav.getPropertyManagerKey());
            items.add(item);

            //for file-based assays, append any associated queries
            List<QueryDefinition> queries = schema.getFileBasedAssayProviderScopedQueries();
            for (QueryDefinition qd : queries)
            {
                TableInfo query = qd.getTable(new ArrayList<QueryException>(), true);
                TabbedReportItem qItem = new TabbedReportItem(this, schema.getSchemaName(), qd.getName(), p.getName() + ": " + query.getTitle(), _providerName);
                qItem.setVisible(nav.isVisible(c, u));
                qItem.setOwnerKey(nav.getPropertyManagerKey());
                items.add(qItem);
            }
        }
        return Collections.unmodifiableList(items);
    }

    @NotNull
    public Set<ClientDependency> getClientDependencies()
    {
        return Collections.emptySet();
    }

    public JSONObject getJsonObject(JSONObject parent, String key)
    {
        return parent.containsKey(key) ? parent.getJSONObject(key): new JSONObject();
    }

    public Module getOwningModule()
    {
        return _module;
    }

    public List<NavItem> getSummary(Container c, User u)
    {
        List<NavItem> items = new ArrayList<NavItem>();

        for (ExpProtocol p : getProtocols(c))
        {
            boolean visible = new AssayNavItem(this, p).isVisible(c, u);
            if (visible)
            {
                ExpRun[] runs = p.getExpRuns();
                Integer totalRuns = 0;
                for (ExpRun run : runs)
                {
                    Container runContainer = run.getContainer();
                    if (runContainer.equals(c) || (runContainer.isWorkbookOrTab() && c.equals(runContainer.getParent())))
                    {
                        totalRuns++;
                    }
                }

                items.add(new SingleNavItem(this, p.getName() + " Runs", totalRuns.toString(), new DetailsURL(PageFlowUtil.urlProvider(AssayUrls.class).getAssayRunsURL(c, p)), LaboratoryService.NavItemCategory.data.name()));
            }
        }

        return Collections.unmodifiableList(items);
    }
}
