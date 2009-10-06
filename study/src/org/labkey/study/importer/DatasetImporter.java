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

package org.labkey.study.importer;

import org.apache.xmlbeans.XmlException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.Container;
import org.labkey.api.study.StudyImportException;
import org.labkey.api.study.InvalidFileException;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.XmlBeansUtil;
import org.labkey.api.util.XmlValidationException;
import org.labkey.study.model.DatasetReorderer;
import org.labkey.study.model.StudyImpl;
import org.labkey.study.model.StudyManager;
import org.labkey.study.xml.DatasetsDocument;
import org.labkey.study.xml.StudyDocument;
import org.springframework.validation.BindException;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * User: adam
 * Date: May 16, 2009
 * Time: 9:42:02 PM
 */
public class DatasetImporter
{
    boolean process(StudyImpl study, ImportContext ctx, File root, BindException errors) throws IOException, SQLException, DatasetImportUtils.DatasetLockExistsException, XmlException, StudyImportException
    {
        StudyDocument.Study.Datasets datasetsXml = ctx.getStudyXml().getDatasets();

        if (null != datasetsXml)
        {
            File datasetDir = getDatasetDirectory(ctx, root);

            List<Integer> orderedIds = null;
            Map<String, DatasetImportProperties> extraProps = null;
            SchemaReader reader = null;
            DatasetsDocument.Datasets manifestDatasetsXml = getDatasetsManifest(ctx, root, true);  // Log the first manifest load

            if (null != manifestDatasetsXml)
            {
                Container c = ctx.getContainer();

                if (!PageFlowUtil.nullSafeEquals(manifestDatasetsXml.getDefaultDateFormat(), StudyManager.getInstance().getDefaultDateFormatString(c)))
                    StudyManager.getInstance().setDefaultDateFormatString(c, manifestDatasetsXml.getDefaultDateFormat());

                if (!PageFlowUtil.nullSafeEquals(manifestDatasetsXml.getDefaultNumberFormat(), StudyManager.getInstance().getDefaultNumberFormatString(c)))
                    StudyManager.getInstance().setDefaultNumberFormatString(c, manifestDatasetsXml.getDefaultNumberFormat());

                DatasetsDocument.Datasets.Datasets2.Dataset[] datasets = manifestDatasetsXml.getDatasets().getDatasetArray();

                extraProps = getDatasetImportProperties(manifestDatasetsXml);

                orderedIds = new ArrayList<Integer>(datasets.length);

                for (DatasetsDocument.Datasets.Datasets2.Dataset dataset : datasets)
                    orderedIds.add(dataset.getId());

                String metaDataFilename = manifestDatasetsXml.getMetaDataFile();

                if (null != metaDataFilename)
                {
                    File schemaXmlFile = ctx.getStudyFile(root, datasetDir, metaDataFilename, datasetsXml.getFile());
                    ctx.getLogger().info("Loading dataset schema from " + StudyImportException.getRelativePath(root, schemaXmlFile));
                    reader = new SchemaXmlReader(study, ctx, root, schemaXmlFile, extraProps);
                }
            }

            if (null == reader)
            {
                StudyDocument.Study.Datasets.Schema schema = datasetsXml.getSchema();

                if (null != schema)
                {
                    String schemaTsvSource = schema.getFile();
                    String labelColumn = schema.getLabelColumn();
                    String typeNameColumn = schema.getTypeNameColumn();
                    String typeIdColumn = schema.getTypeIdColumn();

                    File schemaTsvFile = ctx.getStudyFile(root, datasetDir, schemaTsvSource);

                    ctx.getLogger().info("Loading dataset schema from " + StudyImportException.getRelativePath(root, schemaTsvFile));
                    reader = new SchemaTsvReader(study, schemaTsvFile, labelColumn, typeNameColumn, typeIdColumn, extraProps, errors);
                }
            }

            if (null != reader)
            {
                if (!StudyManager.getInstance().importDatasetSchemas(study, ctx.getUser(), reader, errors))
                    return false;
            }

            if (null != orderedIds)
            {
                DatasetReorderer reorderer = new DatasetReorderer(study, ctx.getUser());
                reorderer.reorderDatasets(orderedIds);
            }
        }

        return true;
    }


    public static File getDatasetDirectory(ImportContext ctx, File root) throws StudyImportException
    {
        StudyDocument.Study.Datasets datasetsXml = ctx.getStudyXml().getDatasets();

        if (null != datasetsXml)
        {
            if (null == datasetsXml.getDir())
                return root;

            return ctx.getStudyDir(root, datasetsXml.getDir());
        }

        return null;
    }


    @Nullable
    public static DatasetsDocument.Datasets getDatasetsManifest(ImportContext ctx, File root, boolean log) throws XmlException, IOException, StudyImportException
    {
        File datasetDir = getDatasetDirectory(ctx, root);

        if (null != datasetDir)
        {
            String datasetsXmlFilename = ctx.getStudyXml().getDatasets().getFile();

            if (null != datasetsXmlFilename)
            {
                File datasetsXmlFile = ctx.getStudyFile(root, datasetDir, datasetsXmlFilename);

                try
                {
                    if (log)
                        ctx.getLogger().info("Loading datasets manifest from " + StudyImportException.getRelativePath(root, datasetsXmlFile));

                    DatasetsDocument doc = DatasetsDocument.Factory.parse(datasetsXmlFile);
                    XmlBeansUtil.validateXmlDocument(doc, ctx.getLogger());
                    return doc.getDatasets();
                }
                catch (XmlException e)
                {
                    throw new InvalidFileException(root, datasetsXmlFile, e);
                }
                catch (XmlValidationException e)
                {
                    throw new InvalidFileException(root, datasetsXmlFile, "File does not conform to datasets.xsd");
                }
            }
        }

        return null;
    }


    public static Map<String, DatasetImportProperties> getDatasetImportProperties(@NotNull DatasetsDocument.Datasets datasetsXml)
    {
        DatasetsDocument.Datasets.Datasets2.Dataset[] datasets = datasetsXml.getDatasets().getDatasetArray();
        Map<String, DatasetImportProperties> extraProps = new HashMap<String, DatasetImportProperties>(datasets.length);

        for (DatasetsDocument.Datasets.Datasets2.Dataset dataset : datasets)
        {
            DatasetImportProperties props = new DatasetImportProperties(dataset.getId(), dataset.getCategory(), dataset.getCohort(), dataset.getShowByDefault(), dataset.getDemographicData());
            extraProps.put(dataset.getName(), props);
        }

        return extraProps;
    }


    // These are the study-specific dataset properties that are defined in datasets.xml
    public static class DatasetImportProperties
    {
        private final int _id;
        private final String _category;
        private final String _cohort;
        private final boolean _showByDefault;
        private final boolean _demographicData;

        private DatasetImportProperties(int id, String category, String cohort, boolean showByDefault, boolean demographicData)
        {
            _id = id;
            _category = category;
            _cohort = cohort;
            _showByDefault = showByDefault;
            _demographicData = demographicData;
        }

        public int getId()
        {
            return _id;
        }

        public String getCategory()
        {
            return _category;
        }

        public String getCohort()
        {
            return _cohort;
        }

        public boolean isShowByDefault()
        {
            return _showByDefault;
        }

        public boolean isDemographicData()
        {
            return _demographicData;
        }
    }
}
