/*
 * Copyright (c) 2008-2015 LabKey Corporation
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
package org.labkey.pipeline.api;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.XppDriver;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.labkey.api.pipeline.NoSuchJobException;
import org.labkey.api.pipeline.PairSerializer;
import org.labkey.api.pipeline.PipelineJob;
import org.labkey.api.pipeline.PipelineStatusFile;
import org.labkey.api.security.impersonation.AbstractImpersonationContextFactory;
import org.labkey.api.settings.AppProps;
import org.labkey.api.util.GUID;
import org.labkey.api.util.Pair;
import org.labkey.api.util.UnexpectedException;
import org.labkey.pipeline.xstream.FileXStreamConverter;
import org.labkey.pipeline.xstream.TaskIdXStreamConverter;
import org.labkey.pipeline.xstream.URIXStreamConverter;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * <code>PipelineJobMarshaller</code> handles saving a <code>PipelineJob</code> to XML,
 * and restoring it from XML.
 *
 * todo: probably want to have 2 different interfaces here, rather than implementing
 *          JobStore, an throwing UnsupportedOperationException on most of its
 *          methods.
 */
public class PipelineJobMarshaller implements PipelineStatusFile.JobStore
{
    private final AtomicReference<XStream> _xstream = new AtomicReference<>();

    public final XStream getXStream()
    {
        XStream instance = _xstream.get();

        if (instance == null)
        {
            try
            {
                instance = new XStream(new XppDriver());
                instance.registerConverter(new TaskIdXStreamConverter());
                instance.registerConverter(new FileXStreamConverter());
                instance.registerConverter(new URIXStreamConverter());
                // Don't need to remember HTTP session attributes in serialized jobs. They can be quite large.
                // We do want to make sure that we keep tracking other impersonation details for auditing, etc
                // This is set based on the declaring class for the field - see http://xstream.codehaus.org/javadoc/com/thoughtworks/xstream/XStream.html#omitField(java.lang.Class, java.lang.String)
                instance.omitField(AbstractImpersonationContextFactory.class, "_adminSessionAttributes");
                if (!_xstream.compareAndSet(null, instance))
                    instance = _xstream.get();
            }
            catch (Exception e)
            {
                throw new IllegalStateException("Failed to initialize XStream for pipeline jobs.", e);
            }
        }

        return instance;
    }

    public String toXML(PipelineJob job)
    {
        return getXStream().toXML(job);
    }

    public PipelineJob fromXML(String xml)
    {
        return (PipelineJob) getXStream().fromXML(xml);
    }

    /* CONSIDER: create a separate interface? */
    public void storeJob(PipelineJob job) throws NoSuchJobException
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public PipelineJob getJob(String jobId)
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public PipelineJob getJob(int rowId)
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public void retry(String jobId) throws IOException, NoSuchJobException
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public void retry(PipelineStatusFile sf) throws IOException, NoSuchJobException
    {
        throw new UnsupportedOperationException("Method supported only on web server");        
    }

    public void split(PipelineJob job) throws IOException
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public void join(PipelineJob job) throws IOException, NoSuchJobException
    {
        throw new UnsupportedOperationException("Method supported only on web server");
    }

    public String toJSONTest(Object job)
    {
        ObjectMapper mapper = PipelineJob.createObjectMapper();

        try
        {
            String serialized = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(job);
            if (AppProps.getInstance().isDevMode())
            {
                try
                {
                    Object unserialized = fromJSONTest(serialized, job.getClass());
                    if (job instanceof PipelineJob)
                    {
                        List<String> errors = ((PipelineJob)job).compareJobs((PipelineJob)unserialized);
                        if (!errors.isEmpty())
                            LOG.error("Deserialized object differs from original: " + StringUtils.join(errors, ","));
                    }
                }
                catch (Exception e)
                {
                    LOG.error("Unserializing test failed: " + job.getClass(), e);
                }
            }
            return serialized;
        }
        catch (Exception e)
        {
            throw new UnexpectedException(e);
        }

    }

    public Object fromJSONTest(String xml, Class<?> cls)
    {

        ObjectMapper mapper = PipelineJob.createObjectMapper();

        try
        {
            return mapper.readValue(xml, cls);
        }
        catch (Exception e)
        {
            throw new UnexpectedException(e);
        }
    }

    private static Logger LOG = Logger.getLogger(PipelineJobMarshaller.class);

    public static class TestCase extends PipelineJob.TestSerialization
    {

        public static class Inner
        {
            private String _address;
            private int _zip;

            public Inner()
            {

            }
            public Inner(String address, int zip)
            {
                _address = address;
                _zip = zip;
            }

            public String getAddress()
            {
                return _address;
            }

            public int getZip()
            {
                return _zip;
            }
        }

        public static class TestJob3
        {
            private List<List<Object>> objs;

            public TestJob3()
            {

            }

            public List<List<Object>> getObjs()
            {
                return objs;
            }

            public void setObjs(List<List<Object>> objs)
            {
                this.objs = objs;
            }
        }

        public static class TestJob
        {
            private String _name;
            private Timestamp _timestamp;
            private Time _time;
            public GUID _guid;
/*            private int _migrateFilesOption;
            @JsonSerialize(keyUsing = StringKeySerialization.Serializer.class)
            @JsonDeserialize(keyUsing = StringKeySerialization.Deserializer.class)
            private Map<URI, Object> _map;

            @JsonSerialize(keyUsing = ObjectKeySerialization.Serializer.class)
            @JsonDeserialize(keyUsing = ObjectKeySerialization.Deserializer.class)
            private Map<PropertyDescriptor, Object> _propMap;
            private Inner _inner;
            private List<Inner> _list;
            private Object _obj;            */
            @JsonSerialize(using = PairSerializer.class)
            private Pair<Inner, Inner> _innerPair;

            public TestJob()
            {

            }
            public TestJob(String name, int option)
            {
                _name = name;
 /*               _migrateFilesOption = option;
                _map = new HashMap<>();
                _map.put(URI.create("http://google.com"), "fooey");
                _map.put(URI.create("file:///Users/daveb"), 324);
                _map.put(URI.create("http://ftp.census.gov"), new Inner("329 Wiltshire Blvd", 90210));
                _inner = new Inner("3234 Albert Ave", 98101);
                _list = new ArrayList<>();
                _list.add(new Inner("31 Thunder Ave", 64102));
                _list.add(new Inner("34 Boston St", 71101));
                _obj = new Inner("17 Boylston St", 10014);

                _propMap = new HashMap<>();
                _propMap.put(new PropertyDescriptor(null, PropertyType.BIGINT, "foobar", ContainerManager.getRoot()), "foo");
                _propMap.put(new PropertyDescriptor(null, PropertyType.STRING, "stringy", ContainerManager.getRoot()), "str"); */
//                _innerPair = new Pair<>(new Inner("31 Thunder Ave", 64102), new Inner("34 Boston St", 71101));
                _timestamp = new Timestamp(1400938833L);
                _time = new Time(1400938843L);
                _guid = new GUID();

            }

            public String getName()
            {
                return _name;
            }

            public Pair<Inner, Inner> getInnerPair()
            {
                return _innerPair;
            }

            public void setInnerPair(Pair<Inner, Inner> innerPair)
            {
                _innerPair = innerPair;
            }

            public Timestamp getTimestamp()
            {
                return _timestamp;
            }

            public void setTimestamp(Timestamp timestamp)
            {
                _timestamp = timestamp;
            }

            public Time getTime()
            {
                return _time;
            }

            public void setTime(Time time)
            {
                _time = time;
            }
/*            public int getMigrateFilesOption()
            {
                return _migrateFilesOption;
            }
            public Map<URI, Object> getMap()
            {
                return _map;
            }
            public Inner getInner()
            {
                return _inner;
            }      */
        }

        @Test
        public void testSerialize()
        {
            try
            {
                Object job = new TestJob("Johnny", 5);
                testSerialize(job, LOG);

/*                TestJob3 job3 = new TestJob3();
                List<List<Object>> objs = new ArrayList<>();
                List<Object> os = new ArrayList<>();
                os.add("ToMe"); os.add(32); os.add(4.5);
                objs.add(os);
                List<Object> os1 = new ArrayList<>();
                os1.add("FooBar"); os.add(99);
                objs.add(os1);
                job3.setObjs(objs);
                testSerialize(job3, LOG);           */

            }
            catch (Exception e) // ClassNotFoundException e)
            {
                LOG.error("Class not found", e);
            }
        }


    }
}
