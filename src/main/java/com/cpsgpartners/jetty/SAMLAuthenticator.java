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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.NamespaceContext;

import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Authentication.User;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.w3c.dom.Document;

public class SAMLAuthenticator extends LoginAuthenticator {
    private static final Logger LOG = Log.getLogger(SAMLAuthenticator.class);
    private String REDIRECT_URL = "SAML2.0_AUTHN_REDIRECT_URL";
    private String REQUEST_ID = "SAML2.0_AUTHN_REQUEST_ID";

    private String _authMethod = "SAML2.0";

    private String _logoutURI = "/logout";

    private String _metadataURI = "/metadata";

    private String _metadataPath = null;
    private byte[] _metadata = null;

    private RequestHandler _requestHandler;
    private ResponseHandler _responseHandler;
    //This should probably be a timed LRU cache but a Jetty equivalent could not be found and additional dependencies/code complexity is undesired
    private Map<String, Authentication> _samlResponseCache = Collections.synchronizedMap(new WeakHashMap<String, Authentication>());
    
    //Resorted to a singleton since there was no other way to share XML Refs between jetty.xml and jetty-context.xml
    protected static final SAMLAuthenticator _globalInstance = new SAMLAuthenticator();

    public SAMLAuthenticator() {

    }

    public static SAMLAuthenticator getGlobalInstance(){
        return _globalInstance;
    }

    @Override
    public String getAuthMethod() {
        return _authMethod;
    }

    public RequestHandler getRequestHandler() {
        return _requestHandler;
    }

    public void setRequestHandler(RequestHandler requestHandler) {
        this._requestHandler = requestHandler;
    }

    public ResponseHandler getResponseHandler() {
        return _responseHandler;
    }

    public void setResponseHandler(ResponseHandler responseHandler) {
        this._responseHandler = responseHandler;
    }

    public String getLogoutURI() {
        return _logoutURI;
    }

    public void setLogoutURI(String logoutURI) {
        this._logoutURI = logoutURI;
    }

    public String getMetadataURI() {
        return _metadataURI;
    }

    public void setMetadataURI(String metadataURI) {
        this._metadataURI = metadataURI;
    }

    public String getMetadataPath() {
        return _metadataPath;
    }

    public void setMetadataPath(String metadataPath) throws IOException {
        this._metadataPath = metadataPath;
        File f = new File(metadataPath);

        try (FileInputStream fi = new FileInputStream(f)) {
            _metadata = new byte[(int) f.length()];
            fi.read(_metadata);
        }
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        super.setConfiguration(configuration);

    }

    @Override
    public UserIdentity login(String username, Object password, ServletRequest request) {

        UserIdentity user = super.login(username, password, request);
        if (user != null) {
            HttpSession session = ((HttpServletRequest) request).getSession(true);
            Authentication cached = new SessionAuthentication(getAuthMethod(), user, password);
            session.setAttribute(SessionAuthentication.__J_AUTHENTICATED, cached);
            String samlRequestId = ((SAMLResponse) password).getRequestId();
            String previousRequestID = (String) session.getAttribute(REQUEST_ID);
            if (previousRequestID != null) {
                session.removeAttribute(REQUEST_ID);
            }
            if (!samlRequestId.equals(previousRequestID)) {
                _samlResponseCache.put(samlRequestId, cached);
            }
        }
        return user;
    }

    @Override
    public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) throws ServerAuthException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        HttpSession session = req.getSession(true);

        if (_metadata != null && _metadataURI.equals(req.getServletPath())) {
            try {
                res.getOutputStream().write(_metadata);
                return Authentication.SEND_SUCCESS;
            } catch (IOException ioe) {
                throw new ServerAuthException(ioe);
            }
        }

        if (_logoutURI.equals(req.getServletPath())) {
            User user = (User) session.getAttribute(SessionAuthentication.__J_AUTHENTICATED);
            if (user != null) {

                try {
                    _loginService.logout(user.getUserIdentity());
                    SAMLUserPrincipal principal = (SAMLUserPrincipal) user.getUserIdentity().getUserPrincipal();
                    SAMLRequest logoutRequest = _requestHandler.buildLogout(req, principal.getName());
                    session.setAttribute(REQUEST_ID, logoutRequest.getRequestId());
                    String reqString = null;
                    switch (logoutRequest.getMode()) {
                    case ARTIFACT:
                        //TODO fill in rest of request
                        reqString = logoutRequest.getIdpURL() + "?SAMLart=" + logoutRequest.getRequest();
                        break;
                    case POST:
                        res.getWriter().append(logoutRequest.getRequest());
                        return Authentication.SEND_SUCCESS;
                    case REDIRECT:
                        reqString = logoutRequest.getIdpURL() + "?SAMLRequest=" + logoutRequest.getRequest();
                        res.sendRedirect(reqString);
                        return Authentication.SEND_CONTINUE;
                    }

                } catch (IOException ioe) {
                    throw new ServerAuthException(ioe);
                }
            }
        }

        String samlResponseParm = request.getParameter("SAMLResponse");
        String samlRelayStateParm = request.getParameter("RelayState");

        if (!mandatory) {
            return new DeferredAuthentication(this);
        }
        Authentication authentication = (Authentication) session.getAttribute(SessionAuthentication.__J_AUTHENTICATED);
        if (authentication != null) {
            return authentication;
        }
        

        //TODO check for artifact resolve
        if (samlResponseParm == null) {
            try {
                if (DeferredAuthentication.isDeferred(res)) {
                    return Authentication.UNAUTHENTICATED;
                }
                
              //for SSO between contexts sharing this same SAMLAuthenticator instance
                String previousRequestID = (String) session.getAttribute(REQUEST_ID);
                if (previousRequestID != null) { 
                    session.removeAttribute(REQUEST_ID);
                    authentication = (Authentication) _samlResponseCache.get(previousRequestID);
                    if (authentication != null) {                        
                        session.setAttribute(SessionAuthentication.__J_AUTHENTICATED, authentication);
                        return authentication;
                    }
                }

                LOG.debug("SAMLAuthenticator: sending SAML AuthNRequest ");
                StringBuffer requestURL = req.getRequestURL();
                if (req.getQueryString() != null) {
                    requestURL.append("?").append(req.getQueryString());
                }
                req.getSession().setAttribute(REDIRECT_URL, requestURL.toString());
                SAMLRequest authRequest = _requestHandler.buildAuthNRequest(req);
                session.setAttribute(REQUEST_ID, authRequest.getRequestId());
                String reqString = null;
                switch (authRequest.getMode()) {
                case ARTIFACT:
                    //TODO fill in rest of request
                    reqString = authRequest.getIdpURL() + "?SAMLart=" + authRequest.getRequest() + (authRequest.getRelayState() != null ? "&RelayState=" + authRequest.getRelayState() : "");
                    break;
                case POST:
                    res.getWriter().append(authRequest.getRequest());
                    return Authentication.SEND_SUCCESS;
                case REDIRECT:
                    reqString = authRequest.getIdpURL() + "?SAMLRequest=" + authRequest.getRequest() + (authRequest.getRelayState() != null ? "&RelayState=" + authRequest.getRelayState() : "");
                    res.sendRedirect(reqString);
                    return Authentication.SEND_CONTINUE;
                }

            } catch (IOException ioe) {
                throw new ServerAuthException(ioe);
            }
        } else {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(new String(B64Code.decode(samlResponseParm)));
                }
                SAMLResponse samlResponse = _responseHandler.buildSAMLResponse(req, samlResponseParm);

                UserIdentity user = login(null, samlResponse, request);

                if (user != null) {
                    session = req.getSession();
                    String redirectURL = (String) session.getAttribute(REDIRECT_URL);
                    if (redirectURL != null) {
                        session.removeAttribute(REDIRECT_URL);
                        res.sendRedirect(res.encodeRedirectURL(redirectURL));
                        return Authentication.SEND_SUCCESS;
                    } else if (samlRelayStateParm != null) { //TODO see if this is a XSS issue                        
                        res.sendRedirect(res.encodeRedirectURL(samlRelayStateParm));
                        return Authentication.SEND_SUCCESS;
                    } else {
                        return new UserAuthentication(getAuthMethod(), user);
                    }
                }

            } catch (Exception e) {
                LOG.warn(e);
            }
        }
        try {
            res.sendError(HttpServletResponse.SC_FORBIDDEN);
            return Authentication.SEND_FAILURE;
        } catch (IOException e) {
            LOG.warn(e);
        }
        return Authentication.UNAUTHENTICATED;

    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, User validatedUser) throws ServerAuthException {
        return true;
    }

    public static enum SAMLBinding {
        REDIRECT, POST, ARTIFACT;
    }

    public static interface RequestHandler {

        SAMLRequest buildAuthNRequest(HttpServletRequest request) throws IOException;

        SAMLRequest buildLogout(HttpServletRequest request, String nameId) throws IOException;
    }

    public static interface ResponseHandler {

        SAMLResponse buildSAMLResponse(HttpServletRequest request, String assertion) throws IOException;
    }

    public static class SAMLRequest {
        final SAMLBinding _mode;
        final String _request;
        final String _relayState;
        final String _idpURL;
        final String _requestId;

        public SAMLRequest(SAMLBinding mode, String requestId, String request, String relayState, String idpURL) {
            this._mode = mode;
            this._requestId = requestId;
            this._request = request;
            this._relayState = relayState;
            this._idpURL = idpURL;
        }

        public SAMLBinding getMode() {
            return _mode;
        }

        public String getRequestId() {
            return _requestId;
        }

        public String getRequest() {
            return _request;
        }

        public String getRelayState() {
            return _relayState;
        }

        public String getIdpURL() {
            return _idpURL;
        }

    }

    public static class SAMLResponse {
        final Document _response;
        final String _requestId;
        final String _nameId;
        final String[] _roles;
        final Map<String, List<String>> _attributes;
        final X509Certificate _cert;

        public SAMLResponse(Document response, String requestId, String nameId, String[] roles, Map<String, List<String>> attributes, X509Certificate cert) {
            _response = response;
            _requestId = requestId;
            _nameId = nameId;
            _roles = roles;
            _attributes = attributes;
            _cert = cert;
        }

        public Document getResponse() {
            return _response;
        }

        public String getRequestId() {
            return _requestId;
        }

        public String getNameId() {
            return _nameId;
        }

        public String[] getRoles() {
            return _roles;
        }

        public Map<String, List<String>> getAttributes() {
            return _attributes;
        }

    }

    public static class SAMLNamespaceContext implements NamespaceContext {
        public String getNamespaceURI(String prefix) {
            if (prefix == null)
                throw new NullPointerException("null prefix");
            else if ("samlp".equals(prefix))
                return "urn:oasis:names:tc:SAML:2.0:protocol";
            else if ("saml".equals(prefix))
                return "urn:oasis:names:tc:SAML:2.0:assertion";
            else if ("dsig".equals(prefix))
                return XMLSignature.XMLNS;
            else if ("xml".equals(prefix))
                return XMLConstants.XML_NS_URI;
            return XMLConstants.NULL_NS_URI;
        }

        public String getPrefix(String uri) {
            throw new UnsupportedOperationException();
        }

        public Iterator<?> getPrefixes(String uri) {
            throw new UnsupportedOperationException();
        }
    }

}
