/*
 * Copyright (c) 2009 LabKey Corporation
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

package org.labkey.experiment.list;

import org.apache.log4j.Logger;
import org.labkey.api.attachments.AttachmentParent;
import org.labkey.api.attachments.AttachmentService;
import org.labkey.api.data.*;
import org.labkey.api.exp.PropertyType;
import org.labkey.api.exp.list.ListDefinition;
import org.labkey.api.exp.list.ListService;
import org.labkey.api.exp.property.DomainProperty;
import org.labkey.api.query.QueryService;
import org.labkey.api.study.ExternalStudyWriter;
import org.labkey.api.study.ExternalStudyWriterFactory;
import org.labkey.api.study.Study;
import org.labkey.api.study.StudyContext;
import org.labkey.api.util.FileUtil;
import org.labkey.api.util.ResultSetUtil;
import org.labkey.api.writer.VirtualFile;
import org.labkey.data.xml.ColumnType;
import org.labkey.data.xml.TableType;
import org.labkey.data.xml.TablesDocument;
import org.labkey.experiment.controllers.list.ListItemAttachmentParent;

import java.io.*;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/*
* User: adam
* Date: Aug 25, 2009
* Time: 10:11:16 AM
*/
public class ListWriter implements ExternalStudyWriter
{
    private static final Logger LOG = Logger.getLogger(ListWriter.class);
    private static final String DEFAULT_DIRECTORY = "lists";
    public static final String SCHEMA_FILENAME = "lists.xml";

    public String getSelectionText()
    {
        return "Lists";
    }

    public void write(Study study, StudyContext ctx, VirtualFile root) throws Exception
    {
        Container c = ctx.getContainer();
        Map<String, ListDefinition> lists = ListService.get().getLists(c);

        if (!lists.isEmpty())
        {
            ctx.getStudyXml().addNewLists().setDir(DEFAULT_DIRECTORY);
            VirtualFile listsDir = root.getDir(DEFAULT_DIRECTORY);

            // Create meta data doc
            TablesDocument tablesDoc = TablesDocument.Factory.newInstance();
            TablesDocument.Tables tablesXml = tablesDoc.addNewTables();

            for (Map.Entry<String, ListDefinition> entry : lists.entrySet())
            {
                ListDefinition def = entry.getValue();
                TableInfo ti = def.getTable(ctx.getUser());

                // Write meta data
                TableType tableXml = tablesXml.addNewTable();
                ListTableInfoWriter xmlWriter = new ListTableInfoWriter(ti, def, getColumnsToExport(ti, true));
                xmlWriter.writeTable(tableXml);

                // Write data
                Collection<ColumnInfo> columns = getColumnsToExport(ti, false);

                if (!columns.isEmpty())
                {
                    List<DisplayColumn> displayColumns = new LinkedList<DisplayColumn>();

                    for (ColumnInfo col : columns)
                        displayColumns.add(new ListExportDataColumn(col));

                    ResultSet rs = QueryService.get().select(ti, columns, null, null);
                    TSVGridWriter tsvWriter = new TSVGridWriter(rs, displayColumns);
                    tsvWriter.setColumnHeaderType(TSVGridWriter.ColumnHeaderType.propertyName);
                    PrintWriter out = listsDir.getPrintWriter(def.getName() + ".tsv");
                    tsvWriter.write(out);     // NOTE: TSVGridWriter closes PrintWriter and ResultSet

                    writeAttachments(ti, def, c, listsDir);
                }
            }

            listsDir.saveXmlBean(SCHEMA_FILENAME, tablesDoc);
        }
    }

    private void writeAttachments(TableInfo ti, ListDefinition def, Container c, VirtualFile listsDir) throws SQLException, IOException
    {
        List<ColumnInfo> attachmentColumns = new ArrayList<ColumnInfo>();

        for (DomainProperty prop : def.getDomain().getProperties())
            if (prop.getPropertyDescriptor().getPropertyType() == PropertyType.ATTACHMENT)
                attachmentColumns.add(ti.getColumn(prop.getName()));

        if (!attachmentColumns.isEmpty())
        {
            VirtualFile listDir = listsDir.getDir(def.getName());
            Map<String, FileNameUniquifier> uniquifiers = new HashMap<String, FileNameUniquifier>();

            for (ColumnInfo attachmentColumn : attachmentColumns)
                uniquifiers.put(attachmentColumn.getName(), new FileNameUniquifier());

            List<ColumnInfo> selectColumns = new ArrayList<ColumnInfo>(attachmentColumns);
            selectColumns.add(0, ti.getColumn("EntityId"));

            ResultSet rs = null; 

            try
            {
                rs = QueryService.get().select(ti, selectColumns, null, null);

                while(rs.next())
                {
                    String entityId = rs.getString(1);
                    AttachmentParent listItemParent = new ListItemAttachmentParent(entityId, c);

                    rs.getString(1);
                    int sqlColumn = 2;

                    for (ColumnInfo attachmentColumn : attachmentColumns)
                    {
                        String filename = rs.getString(sqlColumn++);

                        // Item might not have an attachment in this column
                        if (null == filename)
                            continue;

                        String columnName = attachmentColumn.getColumnName();
                        VirtualFile columnDir = listDir.getDir(columnName);

                        InputStream is = null;
                        OutputStream os = null;

                        try
                        {
                            is = AttachmentService.get().getInputStream(listItemParent, filename);
                            FileNameUniquifier uniquifier = uniquifiers.get(columnName);
                            os = columnDir.getOutputStream(uniquifier.uniquify(filename));
                            FileUtil.copyData(is, os);
                        }
                        catch (FileNotFoundException e)
                        {
                            // Shouldn't happen... but just skip this file in production if it does
                            assert false;
                        }
                        finally
                        {
                            if (null != is)
                                is.close();
                            if (null != os)
                                os.close();
                        }
                    }
                }
            }
            finally
            {
                ResultSetUtil.close(rs);
            }
        }
    }

    private Collection<ColumnInfo> getColumnsToExport(TableInfo tinfo, boolean metadata)
    {
        Collection<ColumnInfo> columns = new LinkedList<ColumnInfo>();

        for (ColumnInfo column : tinfo.getColumns())
            if (column.isUserEditable() || (metadata && column.isKeyField()))
                columns.add(column);

        return columns;
    }


    // We just want the underlying value, not the lookup
    private static class ListExportDataColumn extends DataColumn
    {
        private ListExportDataColumn(ColumnInfo col)
        {
            super(col);
        }

        @Override
        public Object getDisplayValue(RenderContext ctx)
        {
            return getValue(ctx);
        }
    }

    private static class ListTableInfoWriter extends TableInfoWriter
    {
        private final ListDefinition _def;
        private final Map<String, DomainProperty> _properties = new HashMap<String, DomainProperty>();

        protected ListTableInfoWriter(TableInfo ti, ListDefinition def, Collection<ColumnInfo> columns)
        {
            super(ti, columns, null);
            _def = def;

            for (DomainProperty prop : _def.getDomain().getProperties())
                _properties.put(prop.getName(), prop);
        }

        @Override
        public void writeTable(TableType tableXml)
        {
            super.writeTable(tableXml);
            tableXml.setPkColumnName(_def.getKeyName());
        }

        @Override
        public void writeColumn(ColumnInfo column, ColumnType columnXml)
        {
            super.writeColumn(column, columnXml);

            String columnName = column.getName();

            if (columnName.equals(_def.getKeyName()))
            {
                columnXml.setIsKeyField(true);

                if (column.isAutoIncrement())
                    columnXml.setIsAutoInc(true);
            }
            else
            {
                PropertyType propType = _properties.get(columnName).getPropertyDescriptor().getPropertyType();

                if (propType == PropertyType.ATTACHMENT)
                    columnXml.setDatatype(propType.getXmlName());
            }
        }
    }

    public static class Factory implements ExternalStudyWriterFactory
    {
        public ExternalStudyWriter create()
        {
            return new ListWriter();
        }
    }
}
