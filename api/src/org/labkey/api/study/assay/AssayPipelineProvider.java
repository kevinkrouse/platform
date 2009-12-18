package org.labkey.api.study.assay;

import org.labkey.api.pipeline.PipelineProvider;
import org.labkey.api.pipeline.PipeRoot;
import org.labkey.api.pipeline.PipelineAction;
import org.labkey.api.module.Module;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.view.ViewContext;
import org.labkey.api.view.NavTree;
import org.labkey.api.view.ActionURL;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.exp.api.ExpObject;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.security.permissions.InsertPermission;
import org.labkey.api.security.permissions.AdminPermission;

import java.util.List;
import java.util.Collections;
import java.io.File;

/**
 * User: jeckels
 * Date: Dec 16, 2009
 */
public class AssayPipelineProvider extends PipelineProvider
{
    private final FileEntryFilter _filter;
    private AssayProvider _assayProvider;
    private final String _actionDescription;

    public AssayPipelineProvider(Class<? extends Module> moduleClass, FileEntryFilter filter, AssayProvider assayProvider, String actionDescription)
    {
        this(assayProvider.getName(), moduleClass, filter, assayProvider, actionDescription);
    }

    /** Default pipeline provider name is the same as the provider's name, but allow it to be overridden by subclasses */
    protected AssayPipelineProvider(String name, Class<? extends Module> moduleClass, FileEntryFilter filter, AssayProvider assayProvider, String actionDescription)
    {
        super(name, ModuleLoader.getInstance().getModule(moduleClass));
        _filter = filter;
        _assayProvider = assayProvider;
        _actionDescription = actionDescription;
    }

    public void updateFileProperties(ViewContext context, PipeRoot pr, PipelineDirectory directory)
    {
        if (!context.getContainer().hasPermission(context.getUser(), InsertPermission.class))
            return;

        File[] files = directory.listFiles(_filter);
        if (files != null && files.length > 0)
        {
            List<ExpProtocol> assays = AssayService.get().getAssayProtocols(context.getContainer());
            Collections.sort(assays, ExpObject.NAME_COMPARATOR);
            NavTree navTree = new NavTree(_actionDescription);
            for (ExpProtocol protocol : assays)
            {
                if (AssayService.get().getProvider(protocol) == _assayProvider)
                {
                    ActionURL url = PageFlowUtil.urlProvider(AssayUrls.class).getImportURL(context.getContainer(), protocol, pr.relativePath(new File(directory.getURI())), files); 
                    NavTree child = new NavTree("Use " + protocol.getName(), url);
                    child.setId(_actionDescription + ":Use " + protocol.getName());
                    navTree.addChild(child);
                }
            }

            if (context.getContainer().hasPermission(context.getUser(), AdminPermission.class))
            {
                if (navTree.getChildCount() > 0)
                {
                    navTree.addSeparator();
                }

                ActionURL url = PageFlowUtil.urlProvider(AssayUrls.class).getDesignerURL(context.getContainer(), _assayProvider.getName(), context.getActionURL());
                NavTree child = new NavTree("Create New Assay Design", url);
                child.setId(_actionDescription + ":Create Assay Definition");
                navTree.addChild(child);
            }

            if (navTree.getChildCount() > 0)
            {
                directory.addAction(new PipelineAction(navTree, files));
            }
        }
    }
}
