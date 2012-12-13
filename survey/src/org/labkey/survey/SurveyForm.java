package org.labkey.survey;

import org.jetbrains.annotations.Nullable;

/**
 * Created with IntelliJ IDEA.
 * User: cnathe
 * Date: 12/11/12
  */
public class SurveyForm
{
    protected Integer _rowId;
    protected Integer _surveyDesignId;
    protected String _label;
    protected String _status;
    protected String _responsesPk;

    public Integer getRowId()
    {
        return _rowId;
    }

    public void setRowId(@Nullable Integer rowId)
    {
        _rowId = rowId;
    }

    public Integer getSurveyDesignId()
    {
        return _surveyDesignId;
    }

    public void setSurveyDesignId(Integer surveyDesignId)
    {
        _surveyDesignId = surveyDesignId;
    }

    public String getLabel()
    {
        return _label;
    }

    public void setLabel(String label)
    {
        _label = label;
    }

    public String getStatus()
    {
        return _status;
    }

    public void setStatus(String status)
    {
        _status = status;
    }

    public String getResponsesPk()
    {
        return _responsesPk;
    }

    public void setResponsesPk(String responsesPk)
    {
        _responsesPk = responsesPk;
    }
}
