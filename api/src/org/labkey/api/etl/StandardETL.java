/*
 * Copyright (c) 2011 LabKey Corporation
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

package org.labkey.api.etl;

import org.apache.commons.lang.NotImplementedException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.collections.CaseInsensitiveHashMap;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.data.Container;
import org.labkey.api.data.DbScope;
import org.labkey.api.data.TableInfo;
import org.labkey.api.data.UpdateableTableInfo;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.exp.property.DomainProperty;
import org.labkey.api.query.BatchValidationException;
import org.labkey.api.query.FieldKey;
import org.labkey.api.query.ValidationException;
import org.labkey.api.security.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper for code that does not use QueryUpdateService
 *
 *      -- convert basic types
 *      -- handle missing values for property columns
 *      -- required and property validation
 *      -- built-in columns
 *
 *  TODO
 *      -- handle missing values for non-property columns
 */


public class StandardETL implements DataIteratorBuilder
{
    protected enum _op {forInsert, forUpdate}

    final DataIteratorBuilder _inputBuilder;
    final TableInfo _target;
    boolean _useImportAliases = false;
    BatchValidationException _errors;
    final Container _c;
    final User _user;
    boolean _failFast = true;
    _op op = _op.forInsert;

    ValidatorIterator _it;


    public static StandardETL forInsert(TableInfo target, @NotNull DataIteratorBuilder in, @Nullable Container c, @NotNull User user, BatchValidationException errors)
    {
        return new StandardETL(target, in, c, user, errors);
    }


    public static StandardETL forUpdate(TableInfo target, @NotNull DataIteratorBuilder in, @Nullable Container c, @NotNull User user, BatchValidationException errors)
    {
        throw new NotImplementedException();
    }


    protected StandardETL(TableInfo target, @NotNull DataIteratorBuilder in, @Nullable Container c, @NotNull User user, BatchValidationException errors)
    {
        if (!(target instanceof UpdateableTableInfo))
            throw new IllegalArgumentException("Must implement UpdateableTableInfo");
        _inputBuilder = in;
        _target = target;
        _c = c;
        _user = user;
        _errors = errors;
    }


    public void setUseImportAliases(boolean forImport)
    {
        _useImportAliases = forImport;
    }


    public BatchValidationException getErrors()
    {
        return _errors;
    }

    private static class TranslateHelper
    {
        TranslateHelper(ColumnInfo col, DomainProperty dp)
        {
            this.target = col;
            this.dp = dp;
        }
        int indexFrom = 0;
        int indexMv = 0;
        ColumnInfo target=null;
        DomainProperty dp=null;
    }

    @Override
    public DataIterator getDataIterator(BatchValidationException errors)
    {
        if (null != _it)
            return _it;

        Domain d = _target.getDomain();

        Map<String, DomainProperty> propertiesMap = new HashMap<String, DomainProperty>();
        if (null != d)
        {
            for (DomainProperty dp : d.getProperties())
                propertiesMap.put(dp.getPropertyURI(), dp);
        }

        DataIterator input = _inputBuilder.getDataIterator(errors);

        //
        // pass through all the source columns
        // associate each with a target column if possible and handle convert, validate
        //
        // NOTE: although some columns may be matched by propertyURI, I assumie that create/modified etc are bound by name
        //

        input = SimpleTranslator.wrapBuiltInColumns(input, errors, _c, _user, _target);

        Map<String,Integer> sourceColumnsMap = DataIteratorUtil.createColumnAndPropertyMap(input);


        /*
         * NOTE: sbouldn't really need DomainProperty here,
         * but not all information is available on the ColumnInfo
         * notably we need PropertyValidators
         *
         * Anyway match up the columns and property descriptors and keep them in a set of TranslateHeleprs
         */
        List<ColumnInfo> cols = _target.getColumns();
        Map<FieldKey, TranslateHelper> unusedCols = new HashMap<FieldKey,TranslateHelper>(cols.size() * 2);
        Map<String, TranslateHelper> translateHelperMap = new CaseInsensitiveHashMap<TranslateHelper>(cols.size()*4);
        for (ColumnInfo col : cols)
        {
            if (col.isMvIndicatorColumn() || col.isRawValueColumn())
                continue;
            DomainProperty dp = propertiesMap.get(col.getPropertyURI());
            TranslateHelper p = new TranslateHelper(col,dp);
            String uri = col.getPropertyURI();
            if (null != uri)
                 translateHelperMap.put(uri, p);
            unusedCols.put(col.getFieldKey(), p);
        }


        //
        // match up the columns, validate that there is no more than one source column that matches the target column
        //
        ValidationException setupError = new ValidationException();
        ArrayList<ColumnInfo> matches = DataIteratorUtil.matchColumns(input, _target, _useImportAliases, setupError);

        ArrayList<TranslateHelper> targetCols = new ArrayList<TranslateHelper>(input.getColumnCount()+1);
        for (int i=1 ; i<=input.getColumnCount() ; i++)
        {
            ColumnInfo targetCol = matches.get(i);
            TranslateHelper to = null;
            if (null != targetCol)
                to = translateHelperMap.get(targetCol.getPropertyURI());

            if (null != to)
            {
                if (!unusedCols.containsKey(to.target.getFieldKey()))
                    setupError.addGlobalError("Two columns mapped to target column: " + to.target.getName());
                unusedCols.remove(to.target.getFieldKey());
                to.indexFrom = i;
                Integer indexMv = null==to.target.getMvColumnName() ? null : sourceColumnsMap.get(to.target.getMvColumnName());
                to.indexMv = null==indexMv ? 0 : indexMv.intValue();
                targetCols.add(to);
            }
            else
            {
                // pass through unrecognized columns (may be internal column like "_key")
                to = new TranslateHelper(null, null);
                to.indexFrom = i;
                targetCols.add(to);
            }
        }

        //
        // check for unbound columns that are required
        //
        for (TranslateHelper pair : unusedCols.values())
        {
            if (pair.target.isAutoIncrement())
                continue;
            if (!pair.target.isNullable() || (null != pair.dp && pair.dp.isRequired()))
                setupError.addGlobalError("Data does not contain required field: " + pair.target.getName());
        }


        //
        //  CONVERT and VALIDATE iterators
        //
        // set up a SimpleTranslator for conversion and missing-value handling
        //

        SimpleTranslator convert = new SimpleTranslator(input, errors);
        convert.setDebugName("StandardETL convert");
        convert.setFailFast(_failFast);
        convert.setMvContainer(_c);
        ValidatorIterator validate = new ValidatorIterator(convert, errors, _c, _user);
        validate.setDebugName("StandardETL validate");

        for (TranslateHelper pair : targetCols)
        {
            boolean supportsMV = (null != pair.target && null != pair.target.getMvColumnName()) || (null != pair.dp && pair.dp.isMvEnabled());
            int indexConvert;

            if (null == pair.target)
                indexConvert = convert.addColumn(input.getColumnInfo(pair.indexFrom).getName(), pair.indexFrom);
            else if (null == pair.dp)
                indexConvert = convert.addConvertColumn(pair.target, pair.indexFrom, pair.indexMv,  supportsMV);
            else
                indexConvert = convert.addConvertColumn(pair.target.getName(), pair.indexFrom, pair.indexMv, pair.dp.getPropertyDescriptor(), pair.dp.getPropertyDescriptor().getPropertyType());

            if (null != pair.target && !pair.target.isNullable())
                validate.addRequired(indexConvert, false);
            else if (null != pair.dp && pair.dp.isRequired())
                validate.addRequired(indexConvert, true);

            if (null != pair.dp)
                validate.addPropertyValidator(indexConvert, pair.dp.getPropertyDescriptor());
        }

        DataIterator last = validate.hasValidators() ? validate : convert;
        return LoggingDataIterator.wrap(ErrorIterator.wrap(last, errors, false, setupError));
    }
}
