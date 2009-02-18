package org.labkey.api.util;

import java.util.Set;
import java.util.Iterator;
import java.util.Collection;

/**
 * User: jeckels
 * Date: Feb 16, 2009
 */
public class NullPreventingSet<T> implements Set<T>
{
    private Set<T> _set;

    public NullPreventingSet(Set<T> set)
    {
        _set = set;
    }

    public int size()
    {
        return _set.size();
    }

    public boolean isEmpty()
    {
        return _set.isEmpty();
    }

    public boolean contains(Object o)
    {
        return _set.contains(o);
    }

    public Iterator<T> iterator()
    {
        return _set.iterator();
    }

    public Object[] toArray()
    {
        return _set.toArray();
    }

    public <T> T[] toArray(T[] a)
    {
        return _set.toArray(a);
    }

    public boolean add(T t)
    {
        if (t == null)
        {
            throw new IllegalArgumentException("Cannot add null to this set");
        }
        return _set.add(t);
    }

    public boolean remove(Object o)
    {
        return _set.remove(o);
    }

    public boolean containsAll(Collection<?> c)
    {
        return _set.containsAll(c);
    }

    public boolean addAll(Collection<? extends T> c)
    {
        return _set.addAll(c);
    }

    public boolean retainAll(Collection<?> c)
    {
        return _set.retainAll(c);
    }

    public boolean removeAll(Collection<?> c)
    {
        return _set.removeAll(c);
    }

    public void clear()
    {
        _set.clear();
    }

    public boolean equals(Object o)
    {
        return _set.equals(o);
    }

    public int hashCode()
    {
        return _set.hashCode();
    }
}
