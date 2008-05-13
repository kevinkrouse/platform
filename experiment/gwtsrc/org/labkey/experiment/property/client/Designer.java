/*
 * Copyright (c) 2007-2008 LabKey Corporation
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

package org.labkey.experiment.property.client;

import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.core.client.GWT;
import com.google.gwt.user.client.ui.*;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.WindowCloseListener;
import com.google.gwt.user.client.rpc.AsyncCallback;
import org.labkey.api.gwt.client.model.GWTDomain;
import org.labkey.api.gwt.client.model.GWTPropertyDescriptor;
import org.labkey.api.gwt.client.ui.PropertiesEditor;
import org.labkey.api.gwt.client.ui.ImageButton;
import org.labkey.api.gwt.client.ui.LookupServiceAsync;
import org.labkey.api.gwt.client.util.PropertyUtil;
import org.labkey.api.gwt.client.util.ServiceUtil;

import java.util.List;
import java.util.ArrayList;

/**
 * Created by IntelliJ IDEA.
 * User: matthewb
 * Date: May 4, 2007
 * Time: 3:21:44 PM
 */
public class Designer implements EntryPoint
{
    // data
    private String _typeURI;
    private String _returnURL;
    private boolean _allowFileLinkProperties;
    private boolean _allowAttachmentProperties;

    private GWTDomain _domain;

    // UI bits
    private RootPanel _root = null;
    private CellPanel _buttons = null;
    private Label _loading = null;
    private PropertiesEditor _propTable = null;
    boolean _saved = false;

    public void onModuleLoad()
    {
        _typeURI = PropertyUtil.getServerProperty("typeURI");
        _returnURL = PropertyUtil.getServerProperty("returnURL");
        _allowFileLinkProperties = "true".equals(PropertyUtil.getServerProperty("allowFileLinkProperties"));
        _allowAttachmentProperties = "true".equals(PropertyUtil.getServerProperty("allowAttachmentProperties"));

        _root = RootPanel.get("org.labkey.experiment.property.Designer-Root");

        _loading = new Label("Loading...");

        _propTable = new PropertiesEditor(getLookupService());
        _propTable.setMode(PropertiesEditor.modeEdit);

        _buttons = new HorizontalPanel();
        _buttons.add(new CancelButton());
        _buttons.add(new HTML("&nbsp;"));
        _buttons.add(new SubmitButton());

/*
        FlexTable form = new FlexTable();
        form.setText(0,0,"Name");
        form.setWidget(0,1,new TextBox());
        form.setText(1,0,"Description");
        form.setWidget(1,1,new TextBox());
        _root.add(form);
*/
        _root.add(_loading);

/*        Button b = new Button("show", new ClickListener()
        {
            public void onClick(Widget sender)
            {
                String s = "";
                for (int i=0 ; i<_propTable.getPropertyCount(); i++)
                {
                    GWTPropertyDescriptor p = _propTable.getPropertyDescriptor(i);
                    s += p.debugString() + "\n";
                }
                Window.alert(s);
            }
        });
        _root.add(b); */

        asyncGetDomainDescriptor(_typeURI);

        Window.addWindowCloseListener(new WindowCloseListener()
        {
            public void onWindowClosed()
            {
            }

            public String onWindowClosing()
            {
                if (isDirty())
                    return "Changes have not been saved and will be discarded.";
                else
                    return null;
            }
        });
    }


    public boolean isDirty()
    {
        return !_saved && _propTable.isDirty();
    }


    public void setDomain(GWTDomain d)
    {
        if (null == _root)
            return;
        _domain = d;

        _propTable.init(new GWTDomain(d));

        showUI();
    }


    private void showUI()
    {
        if (null != _domain)
        {
            _root.remove(_loading);
            _root.add(_buttons);
            _root.add(_propTable.getWidget());
        }
    }


    class SubmitButton extends ImageButton
    {
        SubmitButton()
        {
            super("Save");
        }

        public void onClick(Widget sender)
        {
            submitForm();
        }
    }


    class CancelButton extends ImageButton
    {
        CancelButton()
        {
            super("Cancel");
        }

        public void onClick(Widget sender)
        {
            cancelForm();
        }
    }


    private void submitForm()
    {
        List errors = _propTable.validate();
        if (null != errors)
        {
            String s = "";
            for (int i=0 ; i<errors.size() ; i++)
                s += errors.get(i) + "\n";
            Window.alert(s);
            return;
        }

        GWTDomain edited = _propTable.getDomainUpdates();
        getService().updateDomainDescriptor(_domain, edited, new AsyncCallback()
        {
            public void onFailure(Throwable caught)
            {
                Window.alert(caught.getMessage());
            }

            public void onSuccess(Object result)
            {
                List errors = (List)result;
                if (null == errors)
                {
                    _saved = true;  // avoid popup warning
                    cancelForm();
                }
                else
                {
                    String s = "";
                    for (int i=0 ; i<errors.size() ; i++)
                        s += errors.get(i) + "\n";
                    Window.alert(s);
                }
            }
        });
    }


    private void cancelForm()
    {
        if (null == _returnURL || _returnURL.length() == 0)
            back();
        else
            navigate(_returnURL);
    }


    public static native void navigate(String url) /*-{
      $wnd.location.href = url;
    }-*/;


    public static native void back() /*-{
        $wnd.history.back();
    }-*/;


    /*
     * SERVER CALLBACKS
     */

    private PropertyServiceAsync _service = null;

    private PropertyServiceAsync getService()
    {
        if (_service == null)
        {
            _service = (PropertyServiceAsync) GWT.create(PropertyService.class);
            ServiceUtil.configureEndpoint(_service, "propertyService");
        }
        return _service;
    }


    void asyncGetDomainDescriptor(String domainURI)
    {
        if (!domainURI.equals("testURI#TYPE"))
        {
            getService().getDomainDescriptor(domainURI, new AsyncCallback()
            {
                    public void onFailure(Throwable caught)
                    {
                        Window.alert(caught.getMessage());
                        _loading.setText("ERROR: " + caught.getMessage());
                    }

                    public void onSuccess(Object result)
                    {
                        GWTDomain d = (GWTDomain)result;
                        d.setAllowFileLinkProperties(_allowFileLinkProperties);
                        d.setAllowAttachmentProperties(_allowAttachmentProperties);
                        setDomain(d);
                    }
            });
        }
        else
        {
            GWTDomain domain = new GWTDomain();
            domain.setDomainURI(domainURI);
            domain.setName("DEM");
            domain.setDescription("I'm a description");

            List list = new ArrayList();

            GWTPropertyDescriptor p = new GWTPropertyDescriptor();
            p.setName("ParticipantID");
            p.setPropertyURI(domainURI + "." + p.getName());
            p.setRangeURI("xsd:double");
            p.setRequired(true);
            list.add(p);

            p = new GWTPropertyDescriptor();
            p.setName("SequenceNum");
            p.setPropertyURI(domainURI + "." + p.getName());
            p.setRangeURI("xsd:double");
            p.setRequired(true);
            list.add(p);

            p = new GWTPropertyDescriptor();
            p.setPropertyId(2);
            p.setName("DEMsex");
            p.setPropertyURI(domainURI + "." + p.getName());
            p.setRangeURI("xsd:int");
            list.add(p);

            p = new GWTPropertyDescriptor();
            p.setPropertyId(3);
            p.setName("DEMhr");
            p.setPropertyURI(domainURI + "." + p.getName());
            p.setRangeURI("xsd:int");
            list.add(p);

            domain.setPropertyDescriptors(list);
            setDomain(domain);
        }
    }

    LookupServiceAsync getLookupService()
    {
        return new LookupServiceAsync()
        {
            public void getContainers(AsyncCallback async)
            {
                getService().getContainers(async);
            }

            public void getSchemas(String containerId, AsyncCallback async)
            {
                getService().getSchemas(containerId, async);
            }

            public void getTablesForLookup(String containerId, String schemaName, AsyncCallback async)
            {
                getService().getTablesForLookup(containerId, schemaName, async);
            }
        };
    }
}
