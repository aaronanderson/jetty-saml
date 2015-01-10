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
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;

import org.eclipse.jetty.server.UserIdentity;

public class SAMLUserIdentity implements UserIdentity {
    private Subject _subject;
    private Principal _principal;
    private Map<String, List<String>> _samlAttributes;
    private List<String> _roles;

    public SAMLUserIdentity(Subject subject, Principal principal, List<String> roles, Map<String, List<String>> samlAttributes) {
        _subject = subject;
        _principal = principal;
        _samlAttributes = samlAttributes;
        _roles = roles;
    }

    public Subject getSubject() {
        return _subject;
    }

    public Principal getUserPrincipal() {
        return _principal;
    }

    public boolean isUserInRole(String role, Scope scope) {
        return _roles.contains(role);
    }

    public Map<String, List<String>> getSAMLAttributes() {
        return _samlAttributes;
    }

}
