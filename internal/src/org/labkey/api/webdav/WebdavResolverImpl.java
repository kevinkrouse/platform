/*
 * Copyright (c) 2008-2010 LabKey Corporation
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

package org.labkey.api.webdav;

import junit.framework.Test;
import junit.framework.TestSuite;
import org.jetbrains.annotations.NotNull;
import org.labkey.api.data.Container;
import org.labkey.api.data.ContainerManager;
import org.labkey.api.security.*;
import org.labkey.api.security.SecurityManager;
import org.labkey.api.security.roles.NoPermissionsRole;
import org.labkey.api.security.roles.ReaderRole;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.util.*;
import org.labkey.api.collections.TTLCacheMap;

import java.beans.PropertyChangeEvent;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.*;


/**
 * Created by IntelliJ IDEA.
 * User: matthewb
 * Date: Apr 28, 2008
 * Time: 2:07:13 PM
 */
public class WebdavResolverImpl implements WebdavResolver
{
    static WebdavResolverImpl _instance = new WebdavResolverImpl(WebdavService.getPath());

    final Path _rootPath;

    private WebdavResolverImpl(Path path)
    {
        _rootPath = path;
    }

    public static WebdavResolver get()
    {
        return _instance;
    }

    public boolean requiresLogin()
    {
        return false;
    }

    public Resource welcome()
    {
        return lookup(Path.rootPath);
    }



    public Path getRootPath()
    {
        return _rootPath;
    }

    public Resource lookup(Path fullPath)
    {
        if (fullPath == null || !fullPath.startsWith(getRootPath()))
            return null;
        Path path = getRootPath().relativize(fullPath).normalize();

        Resource root = getRoot();
        if (path.size() == 0)
            return root;

        // start at the root and work down, to avoid lots of cache misses
        Resource resource = root;
        for (String name : path)
        {
            Resource r = resource.find(name);
            // short circuit the descent at last web folder
            if (null == r  || r instanceof UnboundResource)
                return new UnboundResource(resource.getPath().append(name));
            resource = r;
        }
        if (null == resource)
            resource = new UnboundResource(fullPath);
        return resource;
    }


    WebFolderResource _root = null;

    synchronized Resource getRoot()
    {
        if (null == _root)
            _root = new WebFolderResource(this, ContainerManager.getRoot());
        return _root;
    }


    // Cache with short-lived entries to make webdav perform reasonably.  WebdavResolvedImpl is a singleton, so we
    // end up with just one of these.
    private class FolderCache extends TTLCacheMap<Path, Resource> implements ContainerManager.ContainerListener
    {
        private FolderCache()
        {
            super(1000, 5 * TTLCacheMap.MINUTE, "WebDAV folders");
            ContainerManager.addContainerListener(this);
        }

        public synchronized Resource put(Path key, Resource value)
        {
            return super.put(key,value);
        }

        public synchronized Resource get(Path key)
        {
            return super.get(key);
        }

        public synchronized Resource remove(Path key)
        {
            return super.remove(key);
        }

        public void containerCreated(Container c)
        {
            invalidate(c.getParsedPath().getParent(), false);
        }

        public void containerDeleted(Container c, User user)
        {
            invalidate(c.getParsedPath(), true);
            invalidate(c.getParsedPath().getParent(), false);
        }

        public void propertyChange(PropertyChangeEvent pce)
        {
            ContainerManager.ContainerPropertyChangeEvent evt = (ContainerManager.ContainerPropertyChangeEvent)pce;
            Container c = evt.container;
            try
            {
                switch (evt.property)
                {
                    case PipelineRoot:
                    case Policy:
                    case AttachmentDirectory:
                    case WebRoot:
                    default:
                    {
                        invalidate(c.getParsedPath(), true);
                        break;
                    }
                    case Name:
                    {
                        String oldName = (String)evt.getOldValue();
                        invalidate(c.getParsedPath(), true);
                        invalidate(resolveSibling(c, oldName), true);
                        invalidate(c.getParsedPath().getParent(), false);
                        break;
                    }
                    case Parent:
                    {
                        Container oldParent = (Container)pce.getOldValue();
                        invalidate(c.getParsedPath(), true);
                        invalidate(getParentPath(c), false);
                        invalidate(resolveSibling(c,c.getName()), true);
                        invalidate(oldParent.getParsedPath(), false);
                        break;
                    }
                }
            }
            catch (Exception x)
            {
                clear();
            }
        }


        Path getParentPath(Container c)
        {
            Path p = c.getParsedPath();
            if (p.size() == 0)
                throw new IllegalArgumentException();
            return p.getParent();
        }


        Path resolveSibling(Container c, String name)
        {
            Path p = c.getParsedPath();
            if (p.size() == 0)
                throw new IllegalArgumentException();
            return p.getParent().append(name);
        }


        void invalidate(Path containerPath, boolean recursive)
        {
            Path path = getRootPath().append(containerPath);
            remove(path);
            if (recursive)
                removeUsingPrefix(path);
            if (containerPath.size() == 0)
            {
                synchronized (WebdavResolverImpl.this)
                {
                    _root = null;
                }
            }
        }


        public void removeUsingPrefix(Path prefix)
        {
            // since we're touching all the Entrys anyway, might as well test expired()
            for (Entry<Path, Resource> entry = head.next; entry != head; entry = entry.next)
            {
                if (removeOldestEntry(entry))
                {
                    removeEntry(entry);
                    trackExpiration();
                }
                else if (entry.getKey().startsWith(prefix))
                {
                    removeEntry(entry);
                }
            }
        }
    }


    private FolderCache _folderCache = new FolderCache();


//    private FolderResourceImpl lookupWebFolder(String folder)
//    {
//        boolean isPipelineLink = false;
//        assert(folder.equals("/") || !folder.endsWith("/"));
//        if (!folder.equals("/") && folder.endsWith("/"))
//            folder = folder.substring(0,folder.length()-1);

//        if (folder.endsWith("/" + WIKI_LINK))
//        {
//            folder = folder.substring(0, folder.length()- WIKI_LINK.length()-1);
//            Container c = ContainerManager.getForPath(folder);
//            return new WikiFolderResource(c);
//        }
        
//        if (folder.endsWith("/" + PIPELINE_LINK))
//        {
//            isPipelineLink = true;
//            folder = folder.substring(0, folder.length()- PIPELINE_LINK.length()-1);
//        }

//        Container c = ContainerManager.getForPath(folder);
//        if (null == c)
//        {
//
//            return null;
//        }
//
//        // normalize case of folder
//        folder = isPipelineLink ? c(c,PIPELINE_LINK) : c.getPath();
//
//        FolderResourceImpl resource = _folderCache.get(folder);
//        if (null != resource)
//            return resource;
//
//        if (isPipelineLink)
//        {
//            PipeRoot root = null;
//            try
//            {
//                root = PipelineService.get().findPipelineRoot(c);
//                if (null == root)
//                    return null;
//            }
//            catch (SQLException x)
//            {
//                Logger.getLogger(WebdavResolverImpl.class).error("unexpected exception", x);
//            }
//            resource = new PipelineFolderResource(c, root);
//        }
//        else
//        {
//            AttachmentDirectory dir = null;
//            try
//            {
//                try
//                {
//                    if (c.isRoot())
//                        dir = AttachmentService.get().getMappedAttachmentDirectory(c, false);
//                    else
//                        dir = AttachmentService.get().getMappedAttachmentDirectory(c, true);
//                }
//                catch (AttachmentService.MissingRootDirectoryException  ex)
//                {
//                    /* */
//                }
//            }
//            catch (AttachmentService.UnsetRootDirectoryException x)
//            {
//                /* */
//            }
//            resource = new WebFolderResource(c, dir);
//        }
//
//        _folderCache.put(folder,resource);
//        return resource;
//    }

    public class WebFolderResource extends AbstractCollectionResource implements WebFolder
    {
        WebdavResolver _resolver;
        final Container _c;
//        final AttachmentDirectory _attachmentDirectory;
//        final Resource _attachmentResource;
        ArrayList<String> _children = null;

        WebFolderResource(WebdavResolver resolver, Container c)
        {
            super(resolver.getRootPath().append(c.getParsedPath()));
            _resolver = resolver;
            _c = c;
            _containerId = c.getId();
            setPolicy(c.getPolicy());
//            _attachmentDirectory = root;
//            if (null != _attachmentDirectory)
//                _attachmentResource = AttachmentService.get().getAttachmentResource(getPath(), _attachmentDirectory);
//            else
//                _attachmentResource = null;
        }

        public int getIntPermissions(User user)
        {
            return getPolicy().getPermsAsOldBitMask(user);
        }

        public Container getContainer()
        {
            return _c;
        }

        public boolean exists()
        {
            return true;
        }

        public boolean isCollection()
        {
            return exists();
        }

        public synchronized List<String> getWebFoldersNames(User user)
        {
            if (null == _children)
            {
                List<Container> list = ContainerManager.getChildren(_c);
                _children = new ArrayList<String>(list.size() + 2);
                for (Container aList : list)
                    _children.add(aList.getName());

                for (WebdavService.Provider p : WebdavService.get().getProviders())
                {
                    Set<String> s = p.addChildren(this);
                    if (s != null)
                        _children.addAll(s);
                }
            }

            if (null == user || _children.size() == 0)
                return _children;

            ArrayList<String> ret = new ArrayList<String>();
            for (String name : _children)
            {
                Resource r = lookup(this.getPath().append(name));
                if (null != r && r.canRead(user))
                    ret.add(name);
            }
            return ret;
        }


        @Override 
        public boolean canCreateCollection(User user)
        {
            return false;
        }

        @Override
        public boolean canCreate(User user)
        {
            return false;
//            return null != _attachmentResource && _attachmentResource.canCreate(user);
        }

        @Override
        public boolean canRename(User user)
        {
            return false;
        }

        @Override
        public boolean canDelete(User user)
        {
            return false;
        }

        @Override
        public boolean canWrite(User user)
        {
            return false;
        }


        @NotNull
        public List<String> listNames()
        {
            Set<String> set = new TreeSet<String>();
//            if (null != _attachmentResource)
//                set.addAll(_attachmentResource.listNames());
            set.addAll(getWebFoldersNames(null));
            ArrayList<String> list = new ArrayList<String>(set);
            Collections.sort(list);
            return list;
        }


        public Resource find(String child)
        {
            String name = null;
            for (String folder : getWebFoldersNames(null))
            {
                if (folder.equalsIgnoreCase(child))
                {
                    name = folder;
                    break;
                }
            }
            Container c = getContainer().getChild(child);
            if (name == null && c != null)
                name = c.getName();

            if (name != null)
            {
                Path path = getPath().append(name);
                // check in webfolder cache
                Resource resource = _folderCache.get(path);
                if (null != resource)
                    return resource;

                if (c != null)
                {
//                    AttachmentDirectory dir = null;
//                    try
//                    {
//                        try
//                        {
//                            FileContentService svc = ServiceRegistry.get().getService(FileContentService.class);
//                            if (c.isRoot())
//                                dir = svc.getMappedAttachmentDirectory(c, false);
//                            else
//                                dir = svc.getMappedAttachmentDirectory(c, true);
//                        }
//                        catch (MissingRootDirectoryException ex)
//                        {
//                            /* */
//                        }
//                    }
//                    catch (UnsetRootDirectoryException x)
//                    {
//                        /* */
//                    }
                    resource = new WebFolderResource(_resolver, c);
                }
                else
                {
                    for (WebdavService.Provider p : WebdavService.get().getProviders())
                    {
                        resource = p.resolve(this, name);
                        if (null != resource)
                            break;
                    }
                }

                if (resource != null)
                {
                    _folderCache.put(path, resource);
                    return resource;
                }
            }

//            if (null != _attachmentResource)
//            {
//                Resource r = _attachmentResource.find(child);
//                if (null != r)
//                    return r;
//            }
            return new UnboundResource(this.getPath().append(child));
        }


        @NotNull
        public List<History> getHistory()
        {
            return Collections.emptyList();
        }
    }


    public static class UnboundResource extends AbstractResource
    {
        UnboundResource(String path)
        {
            super(Path.parse(path));
        }

        UnboundResource(Path path)
        {
            super(path);
        }

        public boolean exists()
        {
            return false;
        }

        public boolean isCollection()
        {
            return false;
        }

        public boolean isFile()
        {
            return false;
        }

        @Override
        public Set<Class<? extends Permission>> getPermissions(User user)
        {
            return Collections.emptySet();
        }



        public Resource find(String name)
        {
            return new UnboundResource(this.getPath().append(name));
        }

        public List<String> listNames()
        {
            return Collections.emptyList();
        }

        public List<Resource> list()
        {
            return Collections.emptyList();
        }

        public long getCreated()
        {
            return Long.MIN_VALUE;
        }

        public long getLastModified()
        {
            return Long.MIN_VALUE;
        }

        public InputStream getInputStream(User user) throws IOException
        {
            return null;
        }

        public long copyFrom(User user, FileStream in) throws IOException
        {
            throw new UnsupportedOperationException();
        }

        public long getContentLength()
        {
            return 0;
        }

        @NotNull
        public List<History> getHistory()
        {
            return Collections.emptyList();
        }
    }

//    String c(Container container, String... names)
//    {
//        return c(container.getPath(), names);
//    }
//
//    static String c(Resource r, String... names)
//    {
//        return c(r.getPath(), names);
//    }
//
//    static String c(String path, List<String> names)
//    {
//        return c(path, names.toArray(new String[names.size()]));
//    }
//
//    static String c(String path, String... names)
//    {
//        StringBuilder s = new StringBuilder();
//        s.append(StringUtils.stripEnd(path,"/"));
//        for (String name : names)
//            s.append("/").append(StringUtils.strip(name, "/"));
//        return s.toString();
//    }


    public static class TestCase extends junit.framework.TestCase
    {

        public TestCase()
        {
            super();
        }


        public TestCase(String name)
        {
            super(name);
        }

        Container testContainer = null;
        

        public void testContainers() throws SQLException
        {
            TestContext context = TestContext.get();
            User guest = UserManager.getGuestUser();
            User user = context.getUser();
            assertTrue("login before running this test", null != user);
            assertFalse("login before running this test", user.isGuest());
            
            Container junitContainer = JunitUtil.getTestContainer();
            testContainer = ContainerManager.createContainer(junitContainer, "c" + (new Random().nextInt()));
            Container c = testContainer;

            WebdavResolver resolver = WebdavResolverImpl.get();

            assertNull(resolver.lookup(Path.parse("..")));
            assertNull(resolver.lookup(Path.parse("/..")));
            assertNull(resolver.lookup(Path.parse(c.getPath() + "/./../../..")));

            Path rootPath = resolver.getRootPath();
            Resource root = resolver.lookup(rootPath);
            assertNotNull(root);
            assertTrue(root.isCollection());
            assertTrue(root.canRead(user));
            assertFalse(root.canCreate(user));

            Resource junit = resolver.lookup(rootPath.append(c.getParsedPath()));
            assertNotNull(junit);
            assertTrue(junit.isCollection());

            Path pathTest = c.getParsedPath().append("dav");
            Container cTest = ContainerManager.ensureContainer(pathTest.toString());

            MutableSecurityPolicy policyNone = new MutableSecurityPolicy(cTest);
            policyNone.addRoleAssignment(SecurityManager.getGroup(Group.groupGuests), NoPermissionsRole.class);
            policyNone.addRoleAssignment(user, ReaderRole.class);
            SecurityManager.savePolicy(policyNone);

            Resource rTest = resolver.lookup(rootPath.append(pathTest));
            assertNotNull(rTest);
            assertTrue(rTest.canRead(user));
            assertFalse(rTest.canWrite(user));
            assertNotNull(rTest.parent());
            assertTrue(rTest.parent().isCollection());


            List<String> names = resolver.lookup(junit.getPath()).listNames();
            assertFalse(names.contains("webdav"));
            assertTrue(names.contains("dav"));

            MutableSecurityPolicy policyRead = new MutableSecurityPolicy(cTest);
            policyRead.addRoleAssignment(SecurityManager.getGroup(Group.groupGuests), ReaderRole.class);
            SecurityManager.savePolicy(policyRead);
            rTest = resolver.lookup(rootPath.append(pathTest));
            assertTrue(rTest.canRead(guest));

            ContainerManager.rename(cTest, "webdav");
            Path pathNew = c.getParsedPath().append("webdav");
            assertFalse(resolver.lookup(rootPath.append(pathTest)).exists());
            assertTrue(resolver.lookup(rootPath.append(pathNew)).exists());

            names = resolver.lookup(junit.getPath()).listNames();
            assertTrue(names.contains("webdav"));
            assertFalse(names.contains("dav"));

            Resource rNotFound = resolver.lookup(rootPath.append("NotFound").append(GUID.makeHash()));
            assertFalse(rNotFound.exists());
        }


        public void testNormalize()
        {
            assertNull(FileUtil.normalize(".."));
            assertNull(FileUtil.normalize("/.."));
            assertNull(FileUtil.normalize("/./.."));
            assertEquals(FileUtil.normalize("/dir//down"), "/dir/down");
            assertNull(FileUtil.normalize("/dir/../down/../.."));
            assertEquals(FileUtil.normalize("./dir/..//"), "/");
            assertEquals(FileUtil.normalize("/dir/./../down/"), "/down");
        }


        public void testFileContent()
        {

        }


        public void testPipeline()
        {

        }


        @Override
        protected void tearDown() throws Exception
        {
            if (null != testContainer)
            {
                deleteContainer(testContainer.getParsedPath().append("dav"));
                deleteContainer(testContainer.getParsedPath().append("webdav"));
                deleteContainer(testContainer.getParsedPath());
                testContainer = null;
            }
        }
        

        void deleteContainer(Path path)
        {
            Container x = ContainerManager.getForPath(path);
            if (null != x)
                ContainerManager.delete(x, TestContext.get().getUser());
        }


        public static Test suite()
        {
            return new TestSuite(TestCase.class);
        }
    }
}
