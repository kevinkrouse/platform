package org.labkey.list.model;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.audit.AuditLogService;
import org.labkey.api.data.ActionButton;
import org.labkey.api.data.ButtonBar;
import org.labkey.api.data.Container;
import org.labkey.api.data.DisplayColumn;
import org.labkey.api.data.Sort;
import org.labkey.api.data.TableInfo;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.lists.permissions.DesignListPermission;
import org.labkey.api.module.Module;
import org.labkey.api.query.DefaultSchema;
import org.labkey.api.query.QuerySchema;
import org.labkey.api.query.QuerySettings;
import org.labkey.api.query.QueryView;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.User;
import org.labkey.api.security.permissions.DeletePermission;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.DataView;
import org.labkey.api.view.ViewContext;
import org.labkey.list.controllers.ListController;
import org.labkey.list.view.ViewDesignColumn;
import org.labkey.list.view.ViewHistoryColumn;
import org.springframework.validation.BindException;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Created by joec on 8/18/2014.
 */
public class ListManagerSchema extends UserSchema
{
    private static final Set<String> TABLE_NAMES;
    public static final String LIST_MANAGER = "ListManager";
    public static final String SCHEMA_NAME = "ListManager";

    static
    {
        Set<String> names = new TreeSet<>();
        names.add(LIST_MANAGER);
        TABLE_NAMES = Collections.unmodifiableSet(names);
    }

    public ListManagerSchema(User user, Container container)
    {
        super(SCHEMA_NAME, "Contains list of lists", user, container, ExperimentService.get().getSchema());
        _hidden = true;
    }

    public static void register(Module module)
    {
        DefaultSchema.registerProvider(SCHEMA_NAME, new DefaultSchema.SchemaProvider(module)
        {
            @Override
            public boolean isAvailable(DefaultSchema schema, Module module)
            {
                return true;
            }

            public QuerySchema createSchema(DefaultSchema schema, Module module)
            {
                return new ListManagerSchema(schema.getUser(), schema.getContainer());
            }
        });
    }
    @Nullable
    @Override
    protected TableInfo createTable(String name)
    {
        if(LIST_MANAGER.equalsIgnoreCase(name))
        {
            TableInfo dbTable = getDbSchema().getTable("list");
            ListManagerTable table = new ListManagerTable(this, dbTable);
            table.setName("Available Lists");
            return table;
        }
        else
        {
            return null;
        }
    }

    @Override
    protected QuerySettings createQuerySettings(String dataRegionName, String queryName, String viewName)
    {
        QuerySettings settings = super.createQuerySettings(dataRegionName, queryName, viewName);
        if (LIST_MANAGER.equalsIgnoreCase(queryName))
        {
            settings.setBaseSort(new Sort("Name"));
        }
        return settings;
    }

    @Override
    public QueryView createView(ViewContext context, QuerySettings settings, BindException errors)
    {
        if(settings.getQueryName().equalsIgnoreCase(LIST_MANAGER))
        {
            return new QueryView(this, settings, errors)
            {
                @Override
                protected void populateButtonBar(DataView view, ButtonBar bar)
                {
//                    populateButtonBar(view, bar, false);
                    bar.add(super.createViewButton(getViewItemFilter()));
                    bar.add(super.createPrintButton());
                    bar.add(createExportButton());
                    bar.add(createDeleteButton());
                    bar.add(createCreateNewListButton());
                    bar.add(createImportListArchiveButton());
                }

                private ActionButton createCreateNewListButton()
                {
                    ActionURL urlCreate = new ActionURL(ListController.EditListDefinitionAction.class, getContainer());
                    urlCreate.addReturnURL(getReturnURL());
                    if(urlCreate != null)
                    {
                        ActionButton btnCreate = new ActionButton(urlCreate, "Create New List");
                        btnCreate.setActionType(ActionButton.Action.POST);
                        btnCreate.setDisplayPermission(DesignListPermission.class);
                        return btnCreate;
                    }
                    return null;
                }

                private ActionButton createImportListArchiveButton()
                {
                    ActionURL urlImport = new ActionURL(ListController.ImportListArchiveAction.class, getContainer());
                    urlImport.addReturnURL(getReturnURL());
                    if(urlImport != null)
                    {
                        ActionButton btnImport = new ActionButton(urlImport, "Import List Archive");
                        btnImport.setActionType(ActionButton.Action.POST);
                        btnImport.setDisplayPermission(DesignListPermission.class);
                        return btnImport;
                    }
                    return null;
                }

                @Override
                public ActionButton createDeleteButton()
                {
                    ActionURL urlDelete = new ActionURL(ListController.DeleteListDefinitionAction.class, getContainer());
                    urlDelete.addReturnURL(getReturnURL());
                    if (urlDelete != null)
                    {
                        ActionButton btnDelete = new ActionButton(urlDelete, "Delete");
                        btnDelete.setActionType(ActionButton.Action.POST);
                        btnDelete.isLocked();
                        btnDelete.setDisplayPermission(DeletePermission.class);
                        btnDelete.setRequiresSelection(true, "Are you sure you want to delete the selected row?", "Are you sure you want to delete the selected rows?");
                        return btnDelete;
                    }
                    return null;
                }

                private ActionButton createExportButton()
                {
                    ActionURL urlExport = new ActionURL(ListController.ExportListArchiveAction.class, getContainer());
                    if(urlExport != null)
                    {
                        ActionButton btnExport = new ActionButton(urlExport, "Export Archives");
                        btnExport.setActionType(ActionButton.Action.POST);
                        btnExport.setDisplayPermission(DesignListPermission.class);
                        btnExport.setRequiresSelection(true);
                        return btnExport;
                    }
                    return null;
                }

                @Override
                protected void addDetailsAndUpdateColumns(List<DisplayColumn> ret, TableInfo table)
                {
                    super.addDetailsAndUpdateColumns(ret, table);
                    if (getContainer().hasPermission(getUser(), DesignListPermission.class))
                    {
                        ActionURL urlDesign = new ActionURL(ListController.EditListDefinitionAction.class, getContainer());
                        urlDesign.addParameter("listId", "${ListId}");
                        ret.add(new ViewDesignColumn(urlDesign));
                    }
                    if (AuditLogService.get().isViewable())
                    {
                        ActionURL urlHistory = new ActionURL(ListController.HistoryAction.class, getContainer());
                        urlHistory.addParameter("listId", "${ListId}");
                        ret.add(new ViewHistoryColumn(urlHistory));
                    }
                }
            };
        }
        return  super.createView(context, settings, errors);
    }
    @Override
    public Set<String> getTableNames()
    {
        return TABLE_NAMES;
    }
}
