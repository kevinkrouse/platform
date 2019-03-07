package org.labkey.api.products;

import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.labkey.api.collections.ConcurrentCaseInsensitiveSortedMap;
import org.labkey.api.test.TestWhen;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.ViewContext;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ProductRegistry
{
    private static Logger _logger = Logger.getLogger(ProductRegistry.class);
    private static Map<String, ProductMenuProvider> _productMap = new ConcurrentCaseInsensitiveSortedMap<>();
    private static Map<String, ProductMenuProvider> _sectionMap = new ConcurrentCaseInsensitiveSortedMap<>();
    private static ProductRegistry _instance = new ProductRegistry();

    private ProductRegistry()
    {
        // private to make this a singleton
    }

    public static ProductRegistry get()
    {
        return _instance;
    }

    public boolean containsProductId(String productId)
    {
        return _productMap.containsKey(productId);
    }

    public void registerMenuItemsProvider(ProductMenuProvider provider)
    {

        if (_productMap.containsKey(provider.getProductId()))
            throw new IllegalArgumentException("Product key '" + provider.getProductId() + " already registered by module '" + _productMap.get(provider.getProductId()).getModuleName() + "'");
        Collection<String> sectionNames = provider.getSectionNames();
        Set<String> alreadyRegistered = sectionNames.stream().filter((name) -> _sectionMap.containsKey(name)).collect(Collectors.toSet());
        if (!alreadyRegistered.isEmpty()) {
            String message = alreadyRegistered.stream()
                    .map((cat) -> "'" + cat + "' registered by product '" + _sectionMap.get(cat).getProductId() + "' in module '" +  _sectionMap.get(cat).getModuleName() + "'")
                    .collect(Collectors.joining("; "));
            throw new IllegalArgumentException("Product menu sections already registered: " + message);
        }
        _productMap.put(provider.getProductId(), provider);
        provider.getSectionNames().forEach(name -> _sectionMap.put(name, provider));
    }

    public void unregisterMenuItemsProvider(ProductMenuProvider provider)
    {
        if (_productMap.containsKey(provider.getProductId()))
            _productMap.remove(provider.getProductId());
        provider.getSectionNames().forEach((name) -> {
            if (_sectionMap.containsKey(name))
                _sectionMap.remove(name);
        });
    }

    @NotNull
    public List<MenuSection> getMenuSections(@NotNull ViewContext context, @NotNull String productId, @Nullable Integer itemLimit)
    {
        if (!_productMap.containsKey(productId))
        {
            return Collections.emptyList();
        }
        ProductMenuProvider provider = _productMap.get(productId);
        List<MenuSection> sections = provider.getSections(context, itemLimit);
        // always include the user menu as the last item
        sections.add(new UserInfoMenuSection(context, provider));
        return sections;
    }

    @Nullable
    public MenuSection getMenuSection(@NotNull ViewContext context, @NotNull String name, @Nullable Integer itemLimit)
    {
        if (_sectionMap.containsKey(name))
        {
            return _sectionMap.get(name).getSection(context, name, itemLimit);
        }
        else
        {
            _logger.warn("No product menu provider registered for menu section '" + name + "'.");
            return null;
        }
    }

    @NotNull
    public List<MenuSection> getMenuSections(@NotNull ViewContext context, @NotNull List<String> sectionNames, @Nullable Integer itemLimit)
    {
        List<MenuSection> items = new ArrayList<>();
        sectionNames.forEach((name) -> {
            MenuSection section = getMenuSection(context, name, itemLimit);
            if (section != null)
                items.add(section);
            else
                _logger.warn("No section provided for menu section name '" + name + "'.");
        });
        return items;
    }

    @TestWhen(TestWhen.When.BVT)
    public static class TestCase extends Assert
    {
        private static final String VALID_PRODUCT_ID = "testProductId1";
        private static final String VALID_PRODUCT_ID_2 = "testProductId2";
        private static ProductRegistry registry = ProductRegistry.get();
        private static ProductMenuProvider _provider1 = new TestMenuProvider("testModule", VALID_PRODUCT_ID, List.of("section X", "Section B", "section b2"));
        private static ProductMenuProvider _provider2 = new TestMenuProvider("testModule", VALID_PRODUCT_ID_2, Collections.emptyList());

        private static class TestMenuSection extends MenuSection
        {

            public TestMenuSection(@NotNull ViewContext context, @NotNull String label, @Nullable String iconClass, @Nullable Integer itemLimit)
            {
                super(context, label, iconClass, itemLimit);
            }

            @Override
            protected @NotNull List<MenuItem> getAllItems()
            {
                return Collections.emptyList();
            }
        }
        private static class TestMenuProvider extends ProductMenuProvider
        {
            private String _moduleName;
            private String _productId;
            private Collection<String> _sectionNames;

            public TestMenuProvider(String moduleName, String productId, Collection<String> sectionNames)
            {
                _moduleName = moduleName;
                _productId = productId;
                _sectionNames = sectionNames;
            }

            @Override
            public @NotNull String getModuleName()
            {
                return _moduleName;
            }

            @Override
            public @NotNull String getProductId()
            {
                return _productId;
            }

            @Override
            public @NotNull Collection<String> getSectionNames()
            {
                return _sectionNames;
            }

            @Override
            public @Nullable MenuSection getSection(@NotNull ViewContext context, @NotNull String sectionName, @Nullable Integer itemLimit)
            {
                if (_sectionNames.contains(sectionName))
                    return new TestMenuSection(context, sectionName, sectionName, itemLimit);
                return null;
            }
        }

        @BeforeClass
        public static void setup()
        {
            registry.registerMenuItemsProvider(_provider1);
            registry.registerMenuItemsProvider(_provider2);
        }

        @AfterClass
        public static void tearDown()
        {
            registry.unregisterMenuItemsProvider(_provider1);
            registry.unregisterMenuItemsProvider(_provider2);
        }

        @Test
        public void registerDuplicateProductId()
        {
            try
            {
                registry.registerMenuItemsProvider(new TestMenuProvider("testModule", VALID_PRODUCT_ID, List.of("Section Y", "section Z")));
                fail("No exception thrown when registering a duplicate product id");
            }
            catch (IllegalArgumentException e)
            {
                // this is the expected outcome
                assertTrue(e.getMessage().contains("already registered"));
            }
        }

        @Test
        public void registerDuplicateSections()
        {
            try
            {
                registry.registerMenuItemsProvider(new TestMenuProvider("testModule", "unusedId", List.of("Section A", "SECTION B")));
                fail("No exception thrown when registering a duplicate menu section");
            }
            catch (IllegalArgumentException e)
            {
                // this is the expected outcome
                assertTrue(e.getMessage().contains("'SECTION B' registered"));
            }
        }

        @Test
        public void getMenuSectionsByProductId()
        {
            ViewContext context = HttpView.currentContext();
            assertTrue("Should get no sections when using an unregistered product id", registry.getMenuSections(context, "bogus", null).isEmpty());

            List<MenuSection> sections = registry.getMenuSections(context, VALID_PRODUCT_ID, null);
            assertEquals("Number of sections not as expected", 4, sections.size());
            assertEquals("First section not as expected or with unexpected label", "section X", sections.get(0).getLabel());
            assertEquals("Second section not as expected or with unexpected label", "Section B", sections.get(1).getLabel());
            assertEquals("Third section not as expected or with unexpected label", "section b2", sections.get(2).getLabel());
            assertEquals("Fourth section not as expected or with unexpected label", UserInfoMenuSection.NAME, sections.get(3).getLabel());

            sections = registry.getMenuSections(context, VALID_PRODUCT_ID_2, null);
            assertEquals("Number of menu sections not as expected when provider has no sections", 1, sections.size());
            assertEquals("User section label not as expected", UserInfoMenuSection.NAME,  sections.get(0).getLabel());
        }

        @Test
        public void getMenuSectionsByName()
        {
            ViewContext context = HttpView.currentContext();
            assertTrue("Should get no sections when using unknown names", registry.getMenuSections(context, List.of("Unknown1", "also unknown"), null).isEmpty());

            List<MenuSection> sections = registry.getMenuSections(context, List.of("section X", "Unknown", "section b2"), null);
            assertEquals("Number of sections not as expected", 2, sections.size());
            assertEquals("First section not as expected or with unexpected label", "section X", sections.get(0).getLabel());
            assertEquals("Second section not as expected or with unexpected label", "section b2", sections.get(1).getLabel());
        }
    }

}