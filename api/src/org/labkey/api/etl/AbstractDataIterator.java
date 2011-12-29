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

import org.apache.commons.lang3.StringUtils;
import org.labkey.api.query.BatchValidationException;
import org.labkey.api.query.ValidationException;

/**
 * Created by IntelliJ IDEA.
 * User: matthewb
 * Date: 2011-05-26
 * Time: 2:48 PM
 */
public abstract class AbstractDataIterator implements DataIterator
{
    String _debugName = "";
    BatchValidationException _errors;
    ValidationException _globalError = null;
    ValidationException _rowError = null;

    protected AbstractDataIterator(BatchValidationException errors)
    {
        _errors = errors;
    }

    public void setDebugName(String name)
    {
        _debugName = name;
    }


    @Override
    public String getDebugName()
    {
        return StringUtils.defaultString(_debugName, getClass().getSimpleName());
    }


    protected boolean hasErrors()
    {
        return _errors.hasErrors();
    }


    protected ValidationException getGlobalError()
    {
        if (null == _globalError)
        {
            _globalError = new ValidationException();
            _globalError.setRowNumber(-1);
            _errors.addRowError(_globalError);
        }
        return _globalError;
    }

    protected ValidationException getRowError()
    {
        int row = (Integer)this.get(0);

        if (null == _rowError || row != _rowError.getRowNumber())
        {
            _rowError = new ValidationException();
            _rowError.setRowNumber(row);
            _errors.addRowError(_rowError);
        }
        return _rowError;
    }
}
