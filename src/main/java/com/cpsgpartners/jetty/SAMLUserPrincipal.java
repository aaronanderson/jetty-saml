//
//  ========================================================================
//  Copyright (c) 1995-2014 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package com.cpsgpartners.jetty;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SAMLUserPrincipal implements Principal {
    private final String _name;
    private Map<String, List<String>> _attributes;

    public SAMLUserPrincipal(String name) {
        _name = name;
    }

    public SAMLUserPrincipal(String name, Map<String, List<String>> attributes) {
        _name = name;
        _attributes = Collections.unmodifiableMap(attributes);
    }

    public String getName() {
        return _name;
    }

    public Map<String, List<String>> getAttributes() {
        return _attributes;
    }

}
