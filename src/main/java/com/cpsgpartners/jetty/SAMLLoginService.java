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

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;

import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

import com.cpsgpartners.jetty.SAMLAuthenticator.SAMLResponse;

public class SAMLLoginService extends AbstractLifeCycle implements LoginService {
    private static final Logger LOG = Log.getLogger(SAMLLoginService.class);

    protected IdentityService _identityService = new DefaultIdentityService();
    protected String _name;
    //Resorted to a singleton since there was no other way to share XML Refs between jetty.xml and jetty-context.xml
    protected static final SAMLLoginService _globalInstance = new SAMLLoginService();

    public SAMLLoginService() {

    }

    public SAMLLoginService(String name) {
        setName(name);
    }
    
    public static SAMLLoginService getGlobalInstance(){
        return _globalInstance;
    }

    @Override
    public String getName() {
        return _name;
    }

    public void setName(String name) {
        if (isRunning()) {
            throw new IllegalStateException("Running");
        }

        _name = name;
    }

    /**
     * username will be null since the credentials will contain all the relevant info
     */
    @Override
    public UserIdentity login(String username, Object credentials) {
        SAMLResponse samlResponse = (SAMLResponse) credentials;

        try {

            String nameId = samlResponse.getNameId();
            Map<String, List<String>> attributes = samlResponse.getAttributes();
            String[] roles = samlResponse.getRoles();
            LOG.debug("Server Principal is: " + samlResponse.getNameId());

            //TODO 
            SAMLUserPrincipal user = new SAMLUserPrincipal(nameId, attributes);

            Subject subject = new Subject();
            subject.getPrincipals().add(user);

            return _identityService.newUserIdentity(subject, user, roles);

        } catch (Exception e) {
            LOG.warn(e);
        }
        return null;
    }

    @Override
    public boolean validate(UserIdentity user) {
        return false;
    }

    @Override
    public IdentityService getIdentityService() {
        return _identityService;
    }

    @Override
    public void setIdentityService(IdentityService service) {
        _identityService = service;
    }

    @Override
    public void logout(UserIdentity user) {

    }

}
